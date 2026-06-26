/* fxtls transport library: real-NSS TLS connection to a real server, exposing a
 * tiny send/recv API for Python. The ClientHello is byte-identical to Firefox 152
 * (see fxtls_config.h). HTTP framing is done above this layer in Python.
 *
 * Certificate validation uses NSS's builtin Mozilla root list (libnssckbi) — the
 * same trust store Firefox uses — when verify != 0. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <prinit.h>
#include <prio.h>
#include <prnetdb.h>
#include <prerror.h>
#include <nss.h>
#include <ssl.h>
#include <cert.h>
#include <secmod.h>
#include "fxtls_config.h"

typedef struct { PRFileDesc *fd; char alpn[24]; } fxtls_ctx;

static int g_init = 0;
static int g_roots = 0;   /* 1 once Mozilla roots are loaded */

/* permissive hook used only when verify == 0 (like `curl -k`) */
static SECStatus fxtls__accept(void *arg, PRFileDesc *fd, PRBool cs, PRBool srv) {
    return SECSuccess;
}

/* directory containing this shared library (for locating a vendored libnssckbi) */
static void fxtls__self_dir(char *out, size_t n) {
    Dl_info info;
    out[0] = 0;
    if (dladdr((void *)&g_init, &info) && info.dli_fname) {
        strncpy(out, info.dli_fname, n - 1); out[n - 1] = 0;
        char *slash = strrchr(out, '/'); if (slash) *slash = 0; else out[0] = 0;
    }
}

/* load NSS's builtin Mozilla CA roots (the trust store Firefox uses) */
static void fxtls__load_roots(void) {
    char dir[1024], path[1200];
    const char *env = getenv("FXTLS_CA_MODULE");
    const char *cands[4]; int nc = 0;
    if (env) cands[nc++] = env;
    fxtls__self_dir(dir, sizeof(dir));
    static char p1[1200], p2[1200];
    if (dir[0]) {
        snprintf(p1, sizeof(p1), "%s/vendor/libnssckbi.dylib", dir); cands[nc++] = p1;
        snprintf(p2, sizeof(p2), "%s/libnssckbi.dylib", dir);        cands[nc++] = p2;
    }
    cands[nc++] = "/opt/homebrew/opt/nss/lib/libnssckbi.dylib";
    for (int i = 0; i < nc; i++) {
        if (access(cands[i], R_OK) != 0) continue;
        snprintf(path, sizeof(path),
                 "name=\"Root Certs\" library=\"%s\"", cands[i]);
        SECMODModule *m = SECMOD_LoadUserModule(path, NULL, PR_FALSE);
        if (m && m->loaded) { g_roots = 1; return; }
    }
    if (getenv("FXTLS_DEBUG")) fprintf(stderr, "fxtls: could not load Mozilla roots\n");
}

static void fxtls__ensure_init(void) {
    if (g_init) return;
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
    NSS_NoDB_Init(".");
    NSS_SetDomesticPolicy();
    fxtls__load_roots();
    g_init = 1;
}

/* run the Firefox-152 TLS handshake to `host` on an already-connected TCP socket
 * and wrap it in a context. Closes `tcp` and returns NULL on failure. */
static fxtls_ctx *fxtls__finish(PRFileDesc *tcp, const char *host, int verify) {
    PRFileDesc *s = SSL_ImportFD(NULL, tcp);
    if (!s) { PR_Close(tcp); return NULL; }
    if (fxtls_configure(s, 100) != SECSuccess) { PR_Close(s); return NULL; }
    SSL_SetURL(s, host);
    if (verify) SSL_AuthCertificateHook(s, SSL_AuthCertificate, CERT_GetDefaultCertDB());
    else        SSL_AuthCertificateHook(s, fxtls__accept, NULL);
    SSL_ResetHandshake(s, PR_FALSE);
    if (SSL_ForceHandshake(s) != SECSuccess) {
        if (getenv("FXTLS_DEBUG"))
            fprintf(stderr, "fxtls handshake err %d (%s)\n",
                    PR_GetError(), PR_ErrorToName(PR_GetError()));
        PR_Close(s); return NULL;
    }
    fxtls_ctx *c = (fxtls_ctx *)calloc(1, sizeof(*c));
    c->fd = s;
    SSLNextProtoState st; unsigned char buf[24]; unsigned int blen = 0;
    if (SSL_GetNextProto(s, &st, buf, &blen, sizeof(buf)) == SECSuccess && blen) {
        memcpy(c->alpn, buf, blen); c->alpn[blen] = 0;
    }
    return c;
}

/* TCP-connect to host:port, trying all resolved addresses */
static PRFileDesc *fxtls__tcp(const char *host, int port, int to) {
    PRAddrInfo *ai = PR_GetAddrInfoByName(host, PR_AF_UNSPEC, PR_AI_ADDRCONFIG);
    if (!ai) return NULL;
    PRFileDesc *tcp = NULL; void *iter = NULL; PRNetAddr addr;
    while ((iter = PR_EnumerateAddrInfo(iter, ai, (PRUint16)port, &addr)) != NULL) {
        PRFileDesc *s = PR_OpenTCPSocket(PR_NetAddrFamily(&addr));
        if (!s) continue;
        if (PR_Connect(s, &addr, PR_SecondsToInterval(to)) == PR_SUCCESS) { tcp = s; break; }
        PR_Close(s);
    }
    PR_FreeAddrInfo(ai);
    return tcp;
}

fxtls_ctx *fxtls_connect(const char *host, int port, int timeout_s, int verify) {
    fxtls__ensure_init();
    PRFileDesc *tcp = fxtls__tcp(host, port, timeout_s > 0 ? timeout_s : 15);
    return tcp ? fxtls__finish(tcp, host, verify) : NULL;
}

/* connect through an HTTP CONNECT proxy: TCP to proxy, CONNECT to the target,
 * then the Firefox-152 TLS handshake runs end-to-end to the target (the proxy
 * only sees an encrypted tunnel). proxy_auth = base64("user:pass") or "". */
fxtls_ctx *fxtls_connect_proxy(const char *proxy_host, int proxy_port,
                               const char *target_host, int target_port,
                               const char *proxy_auth, int timeout_s, int verify) {
    fxtls__ensure_init();
    int to = timeout_s > 0 ? timeout_s : 15;
    PRFileDesc *tcp = fxtls__tcp(proxy_host, proxy_port, to);
    if (!tcp) return NULL;

    char req[1200];
    int n = (proxy_auth && *proxy_auth)
        ? snprintf(req, sizeof req,
              "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
              "Proxy-Authorization: Basic %s\r\nProxy-Connection: keep-alive\r\n\r\n",
              target_host, target_port, target_host, target_port, proxy_auth)
        : snprintf(req, sizeof req,
              "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Connection: keep-alive\r\n\r\n",
              target_host, target_port, target_host, target_port);
    if (PR_Write(tcp, req, n) != n) { PR_Close(tcp); return NULL; }

    char buf[2048]; int total = 0;
    while (total < (int)sizeof(buf) - 1) {
        PRInt32 r = PR_Recv(tcp, buf + total, sizeof(buf) - 1 - total, 0, PR_SecondsToInterval(to));
        if (r <= 0) { PR_Close(tcp); return NULL; }
        total += r; buf[total] = 0;
        if (strstr(buf, "\r\n\r\n")) break;
    }
    char *sp = strchr(buf, ' ');                 /* "HTTP/1.1 200 ..." */
    if (!sp || sp[1] != '2') {
        if (getenv("FXTLS_DEBUG")) fprintf(stderr, "proxy CONNECT failed: %.40s\n", buf);
        PR_Close(tcp); return NULL;
    }
    return fxtls__finish(tcp, target_host, verify);
}

/* connect through a SOCKS5 proxy (RFC 1928 + user/pass auth RFC 1929); the target
 * hostname is sent to the proxy (DNS resolved proxy-side), then FF152 TLS runs
 * end-to-end. user/pass may be "" for no auth. */
fxtls_ctx *fxtls_connect_socks5(const char *proxy_host, int proxy_port,
                                const char *target_host, int target_port,
                                const char *user, const char *pass,
                                int timeout_s, int verify) {
    fxtls__ensure_init();
    int to = timeout_s > 0 ? timeout_s : 15;
    PRInt32 iv = PR_SecondsToInterval(to);
    PRFileDesc *tcp = fxtls__tcp(proxy_host, proxy_port, to);
    if (!tcp) return NULL;
    unsigned char b[600];
    int has_auth = user && *user, n;

    if (has_auth) { b[0]=5; b[1]=2; b[2]=0; b[3]=2; n=4; }   /* offer none + user/pass */
    else          { b[0]=5; b[1]=1; b[2]=0;        n=3; }    /* offer none */
    if (PR_Write(tcp, b, n) != n) { PR_Close(tcp); return NULL; }
    if (PR_Recv(tcp, b, 2, 0, iv) != 2 || b[0] != 5) { PR_Close(tcp); return NULL; }
    if (b[1] == 2) {                                          /* user/pass auth */
        int ul = (int)strlen(user), pl = pass ? (int)strlen(pass) : 0, k = 0;
        b[k++]=1; b[k++]=(unsigned char)ul; memcpy(b+k,user,ul); k+=ul;
        b[k++]=(unsigned char)pl; if (pl) { memcpy(b+k,pass,pl); k+=pl; }
        if (PR_Write(tcp, b, k) != k) { PR_Close(tcp); return NULL; }
        if (PR_Recv(tcp, b, 2, 0, iv) != 2 || b[1] != 0) { PR_Close(tcp); return NULL; }
    } else if (b[1] != 0) { PR_Close(tcp); return NULL; }    /* no acceptable method */

    int hl = (int)strlen(target_host);
    if (hl > 255) { PR_Close(tcp); return NULL; }
    int k = 0;
    b[k++]=5; b[k++]=1; b[k++]=0; b[k++]=3; b[k++]=(unsigned char)hl;   /* CONNECT, domain */
    memcpy(b+k, target_host, hl); k+=hl;
    b[k++]=(unsigned char)((target_port>>8)&0xff); b[k++]=(unsigned char)(target_port&0xff);
    if (PR_Write(tcp, b, k) != k) { PR_Close(tcp); return NULL; }

    if (PR_Recv(tcp, b, 4, 0, iv) != 4 || b[1] != 0) {       /* VER REP RSV ATYP */
        if (getenv("FXTLS_DEBUG")) fprintf(stderr, "socks5 connect rep=%d\n", b[1]);
        PR_Close(tcp); return NULL;
    }
    int alen = b[3]==1 ? 4 : b[3]==4 ? 16 : 0;
    if (b[3]==3) { if (PR_Recv(tcp,b,1,0,iv)!=1){PR_Close(tcp);return NULL;} alen=b[0]; }
    int rem = alen + 2;                                       /* bound addr + port, discard */
    while (rem > 0) {
        PRInt32 r = PR_Recv(tcp, b, rem < (int)sizeof(b) ? rem : (int)sizeof(b), 0, iv);
        if (r <= 0) { PR_Close(tcp); return NULL; }
        rem -= r;
    }
    return fxtls__finish(tcp, target_host, verify);
}

int  fxtls_have_roots(void) { fxtls__ensure_init(); return g_roots; }
int  fxtls_alpn(fxtls_ctx *c, char *out, int n) {
    if (!c) return 0;
    int L = (int)strlen(c->alpn); if (L >= n) L = n - 1;
    memcpy(out, c->alpn, L); out[L] = 0; return L;
}
int  fxtls_write(fxtls_ctx *c, const char *b, int n) { return c ? PR_Write(c->fd, b, n) : -1; }
/* read with a 1s timeout so a reader thread wakes periodically to check for
 * shutdown (PR_Shutdown does not reliably interrupt a blocked PR_Read on macOS).
 * returns >0 bytes, 0 EOF, -1 error, -2 timeout. */
int  fxtls_read (fxtls_ctx *c, char *b, int n) {
    if (!c) return -1;
    PRInt32 r = PR_Recv(c->fd, b, n, 0, PR_SecondsToInterval(1));
    if (r < 0 && PR_GetError() == PR_IO_TIMEOUT_ERROR) return -2;
    return r;
}
/* unblock a reader thread blocked in PR_Read without freeing the context */
void fxtls_shutdown(fxtls_ctx *c) { if (c && c->fd) PR_Shutdown(c->fd, PR_SHUTDOWN_BOTH); }
void fxtls_close(fxtls_ctx *c) { if (c) { if (c->fd) PR_Close(c->fd); free(c); } }

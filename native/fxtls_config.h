/* Shared Firefox-152 NSS ClientHello configuration, used by both the CH-probe
 * binary and the transport shared library. Include after the NSS headers. */
#ifndef FXTLS_CONFIG_H
#define FXTLS_CONFIG_H
#include <ssl.h>
#include <sslexp.h>
#include <sslproto.h>
#include <zlib.h>
#include <brotli/decode.h>
#include <zstd.h>

extern SECStatus SSL_SendAdditionalKeyShares(PRFileDesc *fd, unsigned int count);

/* client never compresses its (absent) certificate */
static SECStatus fxtls__comp_encode(const SECItem *in, SECItem *out) { return SECFailure; }

/* real decoders: modern servers (Cloudflare, etc.) send RFC 8879 compressed
 * certificates using one of the algorithms we advertise, so these must work. */
static SECStatus fxtls__dec_zlib(const SECItem *in, unsigned char *out, size_t outLen, size_t *used) {
    uLongf dl = (uLongf)outLen;
    if (uncompress(out, &dl, in->data, in->len) != Z_OK) return SECFailure;
    *used = dl; return SECSuccess;
}
static SECStatus fxtls__dec_brotli(const SECItem *in, unsigned char *out, size_t outLen, size_t *used) {
    size_t dl = outLen;
    if (BrotliDecoderDecompress(in->len, in->data, &dl, out) != BROTLI_DECODER_RESULT_SUCCESS)
        return SECFailure;
    *used = dl; return SECSuccess;
}
static SECStatus fxtls__dec_zstd(const SECItem *in, unsigned char *out, size_t outLen, size_t *used) {
    size_t r = ZSTD_decompress(out, outLen, in->data, in->len);
    if (ZSTD_isError(r)) return SECFailure;
    *used = r; return SECSuccess;
}

/* Configure `fd` so NSS emits a ClientHello byte-identical to Firefox 152.
 * ech_size=100 yields the genuine 281-byte GREASE ECH extension. */
static SECStatus fxtls_configure(PRFileDesc *fd, int ech_size) {
    static const PRUint16 C[] = {
        0x1301,0x1303,0x1302,0xc02b,0xc02f,0xcca9,0xcca8,0xc02c,
        0xc030,0xc00a,0xc013,0xc014,0x009c,0x009d,0x002f,0x0035 };
    static const SSLNamedGroup G[] = {
        ssl_grp_kem_mlkem768x25519, ssl_grp_ec_curve25519, ssl_grp_ec_secp256r1,
        ssl_grp_ec_secp384r1, ssl_grp_ec_secp521r1, ssl_grp_ffdhe_2048, ssl_grp_ffdhe_3072 };
    static const SSLSignatureScheme S[] = {
        0x0403,0x0503,0x0603,0x0804,0x0805,0x0806,0x0401,0x0501,0x0601,0x0203,0x0201 };
    unsigned char alpn[] = { 8,'h','t','t','p','/','1','.','1', 2,'h','2' };
    SSLCertificateCompressionAlgorithm zlib  ={1,"zlib",  fxtls__comp_encode,fxtls__dec_zlib};
    SSLCertificateCompressionAlgorithm brotli={2,"brotli",fxtls__comp_encode,fxtls__dec_brotli};
    SSLCertificateCompressionAlgorithm zstd  ={3,"zstd",  fxtls__comp_encode,fxtls__dec_zstd};
    SSLVersionRange vr = { SSL_LIBRARY_VERSION_TLS_1_2, SSL_LIBRARY_VERSION_TLS_1_3 };

    if (SSL_OptionSet(fd, SSL_SECURITY, PR_TRUE)) return SECFailure;
    SSL_OptionSet(fd, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE);
    SSL_OptionSet(fd, SSL_ENABLE_GREASE, PR_FALSE);
    SSL_OptionSet(fd, SSL_ENABLE_TLS13_COMPAT_MODE, PR_TRUE);
    SSL_OptionSet(fd, SSL_ENABLE_SESSION_TICKETS, PR_TRUE);
    SSL_OptionSet(fd, SSL_ENABLE_OCSP_STAPLING, PR_TRUE);
    SSL_OptionSet(fd, SSL_ENABLE_SIGNED_CERT_TIMESTAMPS, PR_TRUE);
    SSL_OptionSet(fd, SSL_ENABLE_EXTENDED_MASTER_SECRET, PR_TRUE);
    SSL_OptionSet(fd, SSL_ENABLE_DELEGATED_CREDENTIALS, PR_TRUE);
    SSL_OptionSet(fd, SSL_ENABLE_FALSE_START, PR_TRUE);
    SSL_OptionSet(fd, SSL_ENABLE_ALPN, PR_TRUE);
    SSL_OptionSet(fd, SSL_RECORD_SIZE_LIMIT, 16385);
    SSL_VersionRangeSet(fd, &vr);

    for (int i = 0; i < SSL_GetNumImplementedCiphers(); i++)
        SSL_CipherPrefSet(fd, SSL_GetImplementedCiphers()[i], PR_FALSE);
    for (size_t i = 0; i < sizeof(C)/sizeof(C[0]); i++) SSL_CipherPrefSet(fd, C[i], PR_TRUE);
    SSL_CipherSuiteOrderSet(fd, C, sizeof(C)/sizeof(C[0]));

    SSL_NamedGroupConfig(fd, G, sizeof(G)/sizeof(G[0]));
    SSL_SendAdditionalKeyShares(fd, 2);
    SSL_SignatureSchemePrefSet(fd, S, sizeof(S)/sizeof(S[0]));
    SSL_SetNextProtoNego(fd, alpn, sizeof(alpn));
    SSL_SetCertificateCompressionAlgorithm(fd, zlib);
    SSL_SetCertificateCompressionAlgorithm(fd, brotli);
    SSL_SetCertificateCompressionAlgorithm(fd, zstd);
    SSL_EnableTls13GreaseEch(fd, PR_TRUE);
    SSL_SetTls13GreaseEchSize(fd, (PRUint8)(ech_size ? ech_size : 100));
    return SECSuccess;
}
#endif

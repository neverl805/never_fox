#!/usr/bin/env python3
"""
ClientHello sink: a raw TCP server that captures the TLS ClientHello bytes of
whoever connects (real Firefox OR an impersonation engine), parses them into a
structured fingerprint, and writes the result to JSON.

It never completes the handshake -- it only needs the first client flight, which
is sent in cleartext. This lets us byte-compare real Firefox vs an engine on the
exact same parser, with no browser-automation framework and no sudo/pcap.

Usage:
    python3 hello_sink.py --out FILE.json --label firefox --count 1 --timeout 25
Then point a client at https://localhost:8443/ .
"""
import argparse, json, socket, struct, hashlib, sys, time

# ---- GREASE values (RFC 8701) -------------------------------------------------
GREASE = {0x0a0a,0x1a1a,0x2a2a,0x3a3a,0x4a4a,0x5a5a,0x6a6a,0x7a7a,
          0x8a8a,0x9a9a,0xaaaa,0xbaba,0xcaca,0xdada,0xeaea,0xfafa}
def is_grease(v): return v in GREASE

# ---- name maps (only the ones we care about for Firefox) ----------------------
GROUP_NAMES = {
    0x0017:"secp256r1",0x0018:"secp384r1",0x0019:"secp521r1",
    0x001d:"x25519",0x001e:"x448",
    0x0100:"ffdhe2048",0x0101:"ffdhe3072",0x0102:"ffdhe4096",
    0x11ec:"X25519MLKEM768",0x6399:"X25519Kyber768Draft00",0x639a:"SecP256r1MLKEM768",
}
EXT_NAMES = {
    0x0000:"server_name",0x0005:"status_request",0x000a:"supported_groups",
    0x000b:"ec_point_formats",0x000d:"signature_algorithms",0x0010:"alpn",
    0x0012:"signed_certificate_timestamp",0x0015:"padding",0x0016:"encrypt_then_mac",
    0x0017:"extended_master_secret",0x001b:"compress_certificate",
    0x001c:"record_size_limit",0x0022:"delegated_credentials",
    0x0023:"session_ticket",0x002b:"supported_versions",
    0x002d:"psk_key_exchange_modes",0x0033:"key_share",
    0x0029:"pre_shared_key",0xfe0d:"encrypted_client_hello",0xff01:"renegotiation_info",
}
VER_NAMES={0x0304:"13",0x0303:"12",0x0302:"11",0x0301:"10"}

def u16(b,o): return (b[o]<<8)|b[o+1]

def parse_client_hello(hs: bytes) -> dict:
    """hs = handshake message bytes (type=1 .. ). Returns parsed fingerprint."""
    out={"_offsets":{}}
    assert hs[0]==1, "not a ClientHello"
    o=4                                  # skip handshake type(1)+len(3)
    out["legacy_version"]=u16(hs,o); o+=2
    out["_offsets"]["random"]=(o,32); o+=32           # random (variable -> mask)
    sid_len=hs[o]; o+=1
    out["_offsets"]["session_id"]=(o,sid_len); o+=sid_len
    cs_len=u16(hs,o); o+=2
    ciphers=[u16(hs,o+i) for i in range(0,cs_len,2)]; o+=cs_len
    out["cipher_suites"]=ciphers
    comp_len=hs[o]; o+=1; o+=comp_len    # compression methods
    ext_total=u16(hs,o); o+=2
    end=o+ext_total
    exts=[]; details={}; keyshare_groups=[]; ks_key_offsets=[]; ech_offsets=[]
    while o<end:
        et=u16(hs,o); el=u16(hs,o+2); ed=hs[o+4:o+4+el]; body_off=o+4
        exts.append(et)
        if et==0xfe0d:   # ECH GREASE payload is random per-connection -> mask
            ech_offsets.append((body_off,el))
        if et==0x000a:   # supported_groups
            n=u16(ed,0); details["supported_groups"]=[u16(ed,2+i) for i in range(0,n,2)]
        elif et==0x000b: # ec_point_formats
            details["ec_point_formats"]=list(ed[1:1+ed[0]])
        elif et==0x000d: # signature_algorithms
            n=u16(ed,0); details["signature_algorithms"]=[u16(ed,2+i) for i in range(0,n,2)]
        elif et==0x0010: # ALPN
            alpn=[]; p=2
            while p<len(ed):
                ln=ed[p]; alpn.append(ed[p+1:p+1+ln].decode("latin1")); p+=1+ln
            details["alpn"]=alpn
        elif et==0x002b: # supported_versions
            n=ed[0]; details["supported_versions"]=[u16(ed,1+i) for i in range(0,n,2)]
        elif et==0x002d: # psk_key_exchange_modes
            details["psk_key_exchange_modes"]=list(ed[1:1+ed[0]])
        elif et==0x001c: # record_size_limit
            details["record_size_limit"]=u16(ed,0)
        elif et==0x0000: # server_name
            details["server_name_present"]=True
            if len(ed)>=5: details["sni_host"]=ed[5:].decode("latin1","replace")
        elif et==0x0033: # key_share
            p=2
            while p+4<=len(ed):
                grp=u16(ed,p); kl=u16(ed,p+2)
                keyshare_groups.append(grp)
                ks_key_offsets.append((body_off+p+4, kl))   # mask the key material
                p+=4+kl
            details["key_share_groups"]=keyshare_groups
        elif et==0x001b: # compress_certificate
            n=ed[0]; details["cert_compression_algs"]=[u16(ed,1+i) for i in range(0,n,2)]
        o+=4+el
    out["extensions"]=exts
    out["details"]=details
    out["_offsets"]["key_share_keys"]=ks_key_offsets
    out["_offsets"]["ech"]=ech_offsets
    out["raw_hex"]=hs.hex()
    out.update(_fingerprints(out))
    return out

def _strip(seq): return [x for x in seq if not is_grease(x)]

def _fingerprints(p):
    ciphers=p["cipher_suites"]; exts=p["extensions"]; d=p["details"]
    groups=d.get("supported_groups",[]); pts=d.get("ec_point_formats",[])
    sigs=d.get("signature_algorithms",[])
    # JA3 (legacy_version, ciphers, exts, curves, point_formats) -- raw incl GREASE
    ja3=f'{p["legacy_version"]},{"-".join(map(str,ciphers))},{"-".join(map(str,exts))},{"-".join(map(str,groups))},{"-".join(map(str,pts))}'
    ja3_ng=f'{p["legacy_version"]},{"-".join(map(str,_strip(ciphers)))},{"-".join(map(str,_strip(exts)))},{"-".join(map(str,_strip(groups)))},{"-".join(map(str,pts))}'
    # JA4 (FoxIO)
    sv=[v for v in d.get("supported_versions",[]) if not is_grease(v)]
    ver=VER_NAMES.get(max(sv) if sv else p["legacy_version"],"00")
    sni="d" if d.get("server_name_present") else "i"
    nc=min(len(_strip(ciphers)),99); ne=min(len(_strip(exts)),99)
    alpn=d.get("alpn") or []
    a = (alpn[0][0]+alpn[0][-1]) if alpn else "00"
    ja4_a=f"t{ver}{sni}{nc:02d}{ne:02d}{a}"
    ch=sorted("%04x"%c for c in ciphers if not is_grease(c))
    ja4_b=hashlib.sha256(",".join(ch).encode()).hexdigest()[:12] if ch else "0"*12
    eh=sorted("%04x"%e for e in exts if not is_grease(e) and e not in (0x0000,0x0010))
    sg=["%04x"%s for s in sigs]
    ja4_c_str=",".join(eh)+"_"+",".join(sg)
    ja4_c=hashlib.sha256(ja4_c_str.encode()).hexdigest()[:12]
    ja4=f"{ja4_a}_{ja4_b}_{ja4_c}"
    ja4_r=f"{ja4_a}_{','.join('%04x'%c for c in ciphers if not is_grease(c))}_{','.join(eh)}_{','.join(sg)}"
    return {"ja3":hashlib.md5(ja3.encode()).hexdigest(),"ja3_str":ja3,
            "ja3_nogrease":hashlib.md5(ja3_ng.encode()).hexdigest(),"ja3_nogrease_str":ja3_ng,
            "ja4":ja4,"ja4_r":ja4_r}

def normalized_hex(p):
    """Mask variable fields (random, session_id, key_share keys) so byte-diff
    reflects STRUCTURE, not ephemeral randomness."""
    b=bytearray(bytes.fromhex(p["raw_hex"]))
    for key in ("random","session_id"):
        o,l=p["_offsets"][key]; b[o:o+l]=b"\x00"*l
    for o,l in p["_offsets"]["key_share_keys"]:
        b[o:o+l]=b"\x00"*l
    for o,l in p["_offsets"].get("ech",[]):     # mask ECH GREASE random payload
        b[o:o+l]=b"\x00"*l
    return b.hex()

# ---- recv the ClientHello (handle multi-record fragmentation) ------------------
def recv_client_hello(conn):
    conn.settimeout(8)
    def readn(n):
        d=b""
        while len(d)<n:
            try: c=conn.recv(n-len(d))
            except socket.timeout: break
            if not c: break
            d+=c
        return d
    rec=readn(5)
    if len(rec)<5 or rec[0]!=22: return None
    body=readn((rec[3]<<8)|rec[4])
    if len(body)<4: return None
    hs_len=(body[1]<<16)|(body[2]<<8)|body[3]
    full=bytearray(body)
    while len(full)-4<hs_len:                      # spans more TLS records
        r2=readn(5)
        if len(r2)<5 or r2[0]!=22: break
        full+=readn((r2[3]<<8)|r2[4])
    return bytes(full[:4+hs_len])

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--out",required=True)
    ap.add_argument("--label",default="client")
    ap.add_argument("--port",type=int,default=8443)
    ap.add_argument("--count",type=int,default=1)
    ap.add_argument("--timeout",type=float,default=25)
    a=ap.parse_args()
    s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    try: s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)  # accept v4 too
    except OSError: pass
    s.bind(("::",a.port)); s.listen(16); s.settimeout(a.timeout)
    print(f"[sink:{a.label}] listening on :{a.port}, want {a.count} hello(s), "
          f"timeout {a.timeout}s -> connect https://localhost:{a.port}/",flush=True)
    caps=[]; t0=time.time()
    while len(caps)<a.count and time.time()-t0<a.timeout:
        try: conn,addr=s.accept()
        except socket.timeout: break
        try:
            hs=recv_client_hello(conn)
            if hs:
                p=parse_client_hello(hs)
                p["peer"]=str(addr[0]); p["label"]=a.label
                caps.append(p)
                print(f"[sink:{a.label}] captured #{len(caps)} from {addr[0]}  "
                      f"ja4={p['ja4']}  bytes={len(hs)}",flush=True)
        except Exception as e:
            print(f"[sink:{a.label}] parse error: {e}",flush=True)
        finally:
            try: conn.close()
            except OSError: pass
    s.close()
    if not caps:
        print(f"[sink:{a.label}] NO ClientHello captured",flush=True); sys.exit(2)
    first=caps[0]
    first["normalized_hex"]=normalized_hex(first)
    json.dump(first,open(a.out,"w"),indent=2)
    print(f"[sink:{a.label}] wrote {a.out}",flush=True)

if __name__=="__main__":
    main()

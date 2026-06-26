#!/usr/bin/env python3
"""Field-by-field diff of two captured ClientHellos (real Firefox vs engine).
Emits a markdown report to reports/."""
import json, os, sys, difflib
HERE=os.path.dirname(os.path.abspath(__file__)); PROJ=os.path.dirname(HERE)

CIPHERS={0x1301:"TLS_AES_128_GCM_SHA256",0x1302:"TLS_AES_256_GCM_SHA384",
 0x1303:"TLS_CHACHA20_POLY1305_SHA256",0xc02b:"ECDHE_ECDSA_AES128_GCM_SHA256",
 0xc02f:"ECDHE_RSA_AES128_GCM_SHA256",0xc02c:"ECDHE_ECDSA_AES256_GCM_SHA384",
 0xc030:"ECDHE_RSA_AES256_GCM_SHA384",0xcca9:"ECDHE_ECDSA_CHACHA20_POLY1305",
 0xcca8:"ECDHE_RSA_CHACHA20_POLY1305",0xc013:"ECDHE_RSA_AES128_CBC_SHA",
 0xc014:"ECDHE_RSA_AES256_CBC_SHA",0xc009:"ECDHE_ECDSA_AES128_CBC_SHA",
 0xc00a:"ECDHE_ECDSA_AES256_CBC_SHA",0x009c:"RSA_AES128_GCM_SHA256",
 0x009d:"RSA_AES256_GCM_SHA384",0x002f:"RSA_AES128_CBC_SHA",0x0035:"RSA_AES256_CBC_SHA",
 0x000a:"RSA_3DES_EDE_CBC_SHA",0x0005:"RSA_RC4_128_SHA",0x0004:"RSA_RC4_128_MD5",
 0xc012:"ECDHE_RSA_3DES_EDE_CBC_SHA",0xc011:"ECDHE_RSA_RC4_128_SHA"}
sys.path.insert(0,HERE)
from hello_sink import GREASE,is_grease,GROUP_NAMES,EXT_NAMES

def cn(v): return CIPHERS.get(v,f"0x{v:04x}")
def gn(v): return "GREASE" if is_grease(v) else GROUP_NAMES.get(v,f"0x{v:04x}")
def en(v): return "GREASE" if is_grease(v) else EXT_NAMES.get(v,f"0x{v:04x}")

def named_list(seq,fn): return [("GREASE" if is_grease(v) else fn(v)) for v in seq]

def diff_seq(a,b,fn,label,lines):
    na=named_list(a,fn); nb=named_list(b,fn)
    if na==nb:
        lines.append(f"- **{label}**: ✅ identical ({len(a)} entries)")
        return True
    lines.append(f"- **{label}**: ❌ DIFFER (firefox={len(a)} vs engine={len(b)})")
    sa,sb=set(named_list(a,fn)),set(named_list(b,fn))
    only_ff=[x for x in na if x not in sb]
    only_en=[x for x in nb if x not in sa]
    if only_ff: lines.append(f"    - only in **Firefox**: {only_ff}")
    if only_en: lines.append(f"    - only in **engine** : {only_en}")
    if sa==sb and na!=nb: lines.append("    - same set, **different ORDER**")
    return False

def markers(p):
    d=p["details"]; ex=set(p["extensions"]); g=d.get("supported_groups",[]); ks=d.get("key_share_groups",[])
    return {
     "X25519MLKEM768 in groups":0x11ec in g,
     "X25519MLKEM768 in key_share":0x11ec in ks,
     "ffdhe2048":0x0100 in g, "ffdhe3072":0x0101 in g,
     "record_size_limit":0x001c in ex, "rsl_value":d.get("record_size_limit"),
     "delegated_credentials":0x0022 in ex,
     "encrypted_client_hello(ECH)":0xfe0d in ex,
     "session_ticket":0x0023 in ex, "psk_kem_modes":d.get("psk_key_exchange_modes"),
     "GREASE present":any(is_grease(c) for c in p["cipher_suites"]),
     "ALPN":d.get("alpn"),
    }

def main():
    ff=json.load(open(os.path.join(PROJ,"captures","firefox152_clienthello.json")))
    eng_path=sys.argv[1] if len(sys.argv)>1 else os.path.join(PROJ,"captures","engine_firefox147_clienthello.json")
    en=json.load(open(eng_path))
    L=[]
    L.append("# Firefox 152.0.2 (real)  vs  curl_cffi engine — ClientHello diff\n")
    L.append(f"- real browser: **Firefox 152.0.2** (NSS, captured live on this machine)")
    L.append(f"- engine: **{en.get('label','?')}** (curl_cffi, real NSS build)\n")
    L.append("## Fingerprint hashes\n")
    L.append("| | Firefox 152 | engine |")
    L.append("|---|---|---|")
    L.append(f"| JA3 | `{ff['ja3']}` | `{en['ja3']}` |")
    L.append(f"| JA4 | `{ff['ja4']}` | `{en['ja4']}` |")
    L.append(f"| JA3(no-GREASE) | `{ff['ja3_nogrease']}` | `{en['ja3_nogrease']}` |")
    match = "✅ MATCH" if ff['ja3']==en['ja3'] else "❌ MISMATCH"
    L.append(f"\n**TLS ClientHello verdict: {match}**\n")
    L.append("## Layer-by-layer\n")
    diff_seq(ff["cipher_suites"],en["cipher_suites"],cn,"cipher_suites (ordered)",L)
    diff_seq(ff["extensions"],en["extensions"],lambda v:EXT_NAMES.get(v,f"0x{v:04x}"),"extensions (ordered)",L)
    diff_seq(ff["details"].get("supported_groups",[]),en["details"].get("supported_groups",[]),
             lambda v:GROUP_NAMES.get(v,f"0x{v:04x}"),"supported_groups (ordered)",L)
    diff_seq(ff["details"].get("key_share_groups",[]),en["details"].get("key_share_groups",[]),
             lambda v:GROUP_NAMES.get(v,f"0x{v:04x}"),"key_share groups",L)
    diff_seq(ff["details"].get("signature_algorithms",[]),en["details"].get("signature_algorithms",[]),
             lambda v:f"0x{v:04x}","signature_algorithms (ordered)",L)
    diff_seq(ff["details"].get("supported_versions",[]),en["details"].get("supported_versions",[]),
             lambda v:f"0x{v:04x}","supported_versions",L)
    diff_seq(ff["details"].get("ec_point_formats",[]),en["details"].get("ec_point_formats",[]),
             lambda v:str(v),"ec_point_formats",L)
    diff_seq(ff["details"].get("alpn",[]),en["details"].get("alpn",[]),lambda v:str(v),"ALPN",L)

    L.append("\n## Firefox-152 critical markers\n")
    L.append("| marker | Firefox 152 | engine |")
    L.append("|---|---|---|")
    mf,me=markers(ff),markers(en)
    for k in mf:
        a,b=mf[k],me[k]; flag="" if a==b else "  ⚠️"
        L.append(f"| {k} | `{a}` | `{b}`{flag} |")

    # normalized hex diff (random/session_id/key_share masked)
    L.append("\n## Normalized ClientHello byte diff\n")
    L.append("(random, session_id, key_share key-material masked to 0 — so this reflects STRUCTURE)\n")
    a=ff.get("normalized_hex",ff["raw_hex"]); b=en.get("normalized_hex",en["raw_hex"])
    L.append(f"- firefox normalized len: {len(a)//2} bytes")
    L.append(f"- engine   normalized len: {len(b)//2} bytes")
    L.append(f"- identical: {'✅ yes' if a==b else '❌ no'}")

    L.append("\n## Ordered cipher lists (full)\n")
    L.append("| # | Firefox 152 | engine |")
    L.append("|---|---|---|")
    fa,ea=ff["cipher_suites"],en["cipher_suites"]
    for i in range(max(len(fa),len(ea))):
        x=cn(fa[i]) if i<len(fa) else "—"
        y=cn(ea[i]) if i<len(ea) else "—"
        mark="" if x==y else " ⬅️"
        L.append(f"| {i} | {x} | {y}{mark} |")

    out=os.path.join(PROJ,"reports","clienthello_diff.md")
    open(out,"w").write("\n".join(L))
    print("\n".join(L))
    print(f"\n[written] {out}")

if __name__=="__main__":
    main()

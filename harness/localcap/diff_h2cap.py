#!/usr/bin/env python3
"""Diff the full local captures: real Firefox 152 vs fxreq, end to end."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ff = json.load(open(os.path.join(HERE, "firefox_h2cap.json")))
en = json.load(open(os.path.join(HERE, "fxreq_h2cap.json")))
L = []
def p(s=""): L.append(s)

p("# Full local-capture diff — real Firefox 152  vs  fxreq")
p("(both hit the same local HTTPS/h2 server; server logged TLS+h2+headers)\n")

p("## Transport")
p(f"- ALPN: firefox=`{ff['alpn']}`  fxreq=`{en['alpn']}`  {'✅' if ff['alpn']==en['alpn'] else '❌'}\n")

p("## TLS ClientHello")
for k in ("ja3", "ja4"):
    a, b = ff["tls"][k], en["tls"][k]
    p(f"- {k}: {'✅ identical' if a==b else '❌'}  `{a}`" + ("" if a==b else f"  vs  `{b}`"))
p(f"- cipher_suites identical: {'✅' if ff['tls']['cipher_suites']==en['tls']['cipher_suites'] else '❌'}")
p(f"- extensions identical: {'✅' if ff['tls']['extensions']==en['tls']['extensions'] else '❌'}")
fd, ed = ff["tls"]["details"], en["tls"]["details"]
for k in ("supported_groups", "signature_algorithms", "key_share_groups", "record_size_limit", "alpn"):
    a, b = fd.get(k), ed.get(k)
    p(f"- {k}: {'✅' if a==b else '❌ ff='+str(a)+' fx='+str(b)}")
p("")

p("## HTTP/2")
fh, eh = ff.get("http2", {}), en.get("http2", {})
for k in ("akamai_fingerprint",):
    a, b = fh.get(k), eh.get(k)
    p(f"- **{k}**: {'✅ IDENTICAL' if a==b else '❌'}\n    firefox: `{a}`\n    fxreq  : `{b}`")
p(f"- SETTINGS order+values: {'✅' if fh.get('settings')==eh.get('settings') else '❌'}  ff={fh.get('settings')}  fx={eh.get('settings')}")
p(f"- WINDOW_UPDATE: ff={fh.get('window_update')} fx={eh.get('window_update')}  {'✅' if fh.get('window_update')==eh.get('window_update') else '❌'}")
p(f"- PRIORITY frames: ff={fh.get('priority_frames')}  fx={eh.get('priority_frames')}")
p(f"- pseudo-header order: ff={fh.get('pseudo_header_order')} fx={eh.get('pseudo_header_order')}  {'✅' if fh.get('pseudo_header_order')==eh.get('pseudo_header_order') else '❌'}")
p("")

p("## HTTP headers (name + order + value)")
fhl = fh.get("headers", []); ehl = eh.get("headers", [])
fnames = [h[0] for h in fhl if not h[0].startswith(":")]
enames = [h[0] for h in ehl if not h[0].startswith(":")]
p(f"- regular-header ORDER identical: {'✅' if fnames==enames else '❌'}")
if fnames != enames:
    p(f"    firefox: {fnames}")
    p(f"    fxreq  : {enames}")
fdict = {k.lower(): v for k, v in fhl}
edict = {k.lower(): v for k, v in ehl}
p("\n| header | Firefox 152 | fxreq | match |")
p("|---|---|---|---|")
allk = []
for k in [h[0] for h in fhl] + [h[0] for h in ehl]:
    if k not in allk: allk.append(k)
for k in allk:
    a, b = fdict.get(k, "—"), edict.get(k, "—")
    mark = "✅" if a == b else "❌"
    p(f"| `{k}` | `{a}` | `{b}` | {mark} |")

out = os.path.join(HERE, "FULL_DIFF.md")
open(out, "w").write("\n".join(L))
print("\n".join(L))
print(f"\n[written] {out}")

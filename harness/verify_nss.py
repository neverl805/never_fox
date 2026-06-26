#!/usr/bin/env python3
"""Run the native NSS engine (fxtls) against the sink and diff vs real FF152."""
import json, os, socket, subprocess, sys, time
HERE=os.path.dirname(os.path.abspath(__file__)); PROJ=os.path.dirname(HERE)
sys.path.insert(0,HERE)
from hello_sink import parse_client_hello, is_grease, GROUP_NAMES, EXT_NAMES

def wait_port(port,deadline=6.0):
    t0=time.time()
    while time.time()-t0<deadline:
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=0.5): return True
        except OSError: time.sleep(0.1)
    return False

def ech_len(p):
    rp=parse_client_hello(bytes.fromhex(p["raw_hex"]))
    offs=rp["_offsets"].get("ech",[])
    return offs[0][1] if offs else None

def run(port, ech_size, out):
    sink=subprocess.Popen([sys.executable,os.path.join(HERE,"hello_sink.py"),
        "--out",out,"--label",f"nss-ech{ech_size}","--port",str(port),"--count","1","--timeout","12"])
    if not wait_port(port): sink.terminate(); raise RuntimeError("sink not open")
    r=subprocess.run([os.path.join(PROJ,"native","fxtls"),"localhost",str(port),str(ech_size)],
                     capture_output=True,text=True,timeout=15)
    if r.stdout.strip(): print("  engine stdout:",r.stdout.strip())
    if r.stderr.strip(): print("  engine stderr:",r.stderr.strip())
    sink.wait(timeout=15)
    return json.load(open(out)) if os.path.exists(out) else None

def main():
    ech=int(sys.argv[1]) if len(sys.argv)>1 else 100
    port=int(sys.argv[2]) if len(sys.argv)>2 else 8461
    ff=json.load(open(os.path.join(PROJ,"captures","firefox152_clienthello.json")))
    out=os.path.join(PROJ,"captures","engine_nss_clienthello.json")
    p=run(port,ech,out)
    if not p: print("NO capture"); return
    print(f"\n=== native NSS engine (ech_size={ech})  vs  FF152 ===")
    print(f"  JA3 : {p['ja3']}   {'✅' if p['ja3']==ff['ja3'] else '❌ FF='+ff['ja3']}")
    print(f"  JA4 : {p['ja4']}   {'✅' if p['ja4']==ff['ja4'] else '❌ FF='+ff['ja4']}")
    print(f"  ECH payload len: engine={ech_len(p)}  FF152={ech_len(ff)}  {'✅' if ech_len(p)==ech_len(ff) else '❌'}")
    # field diffs
    def names(seq,m): return [('GREASE' if is_grease(v) else m.get(v,hex(v))) for v in seq]
    if p["cipher_suites"]!=ff["cipher_suites"]:
        print("  cipher diff: engine",[hex(c) for c in p["cipher_suites"]])
        print("               FF152 ",[hex(c) for c in ff["cipher_suites"]])
    if p["extensions"]!=ff["extensions"]:
        print("  ext order diff:")
        print("    engine:",names(p["extensions"],EXT_NAMES))
        print("    FF152 :",names(ff["extensions"],EXT_NAMES))
    else:
        print("  extensions: ✅ identical order")
    for k in ("supported_groups","key_share_groups","signature_algorithms","supported_versions","alpn","cert_compression_algs"):
        a=p["details"].get(k); b=ff["details"].get(k)
        if a!=b: print(f"  {k}: engine={a}  FF152={b}  ❌")
    rsl_a=p["details"].get("record_size_limit"); rsl_b=ff["details"].get("record_size_limit")
    print(f"  record_size_limit: engine={rsl_a} FF152={rsl_b} {'✅' if rsl_a==rsl_b else '❌'}")

if __name__=="__main__":
    main()

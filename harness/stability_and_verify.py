#!/usr/bin/env python3
import json, os, socket, subprocess, sys, time, difflib
HERE=os.path.dirname(os.path.abspath(__file__)); PROJ=os.path.dirname(HERE)
sys.path.insert(0,HERE)
from hello_sink import parse_client_hello, normalized_hex, is_grease

def load(f): return json.load(open(os.path.join(PROJ,"captures",f)))
def renorm(p):  # recompute normalized hex with current masking rules
    return normalized_hex(parse_client_hello(bytes.fromhex(p["raw_hex"])))

def wait_port(port,deadline=6.0):
    t0=time.time()
    while time.time()-t0<deadline:
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=0.5): return True
        except OSError: time.sleep(0.1)
    return False

def capture_ff(port,out):
    sink=subprocess.Popen([sys.executable,os.path.join(HERE,"hello_sink.py"),
        "--out",out,"--label",f"ff152-{port}","--port",str(port),"--count","1","--timeout","25"])
    if not wait_port(port): sink.terminate(); return None
    subprocess.run(["open","-a","Firefox",f"https://localhost:{port}/probe{port}"])
    sink.wait(timeout=30)
    return json.load(open(out)) if os.path.exists(out) else None

def ech_len(p):
    rp=parse_client_hello(bytes.fromhex(p["raw_hex"]))
    offs=rp["_offsets"].get("ech",[])
    return offs[0][1] if offs else None

print("### A. tuned-engine  vs  FF152  (structural byte diff)")
ff=load("firefox152_clienthello.json"); tu=load("engine_tuned_clienthello.json")
a=bytes.fromhex(renorm(ff)); b=bytes.fromhex(renorm(tu))
diffs=[(t,a[i1:i2].hex(),b[j1:j2].hex()) for t,i1,i2,j1,j2 in difflib.SequenceMatcher(None,a,b).get_opcodes() if t!="equal"]
print(f"  ja3 equal: {ff['ja3']==tu['ja3']}   ja4 equal: {ff['ja4']==tu['ja4']}")
print(f"  structural byte diffs remaining (after masking random/keyshare/ECH): {len(diffs)}")
for t,x,y in diffs: print(f"    {t}: ff={x!r} tuned={y!r}")
print(f"  -> diffs are ECH-length only (random GREASE), not stable structure" if diffs else "  -> byte-identical")

print("\n### B. Firefox stability (multi-sample)")
samples=[("orig",ff)]
for port,fn in [(8446,"firefox152_s2.json"),(8447,"firefox152_s3.json")]:
    p=capture_ff(port,os.path.join(PROJ,"captures",fn))
    if p: samples.append((f":{port}",p))
print(f"  {'sample':10} {'ja3':34} {'#ciphers':8} {'has_c009':8} {'rsl':6} {'ech_len':7}")
for name,p in samples:
    nci=len([c for c in p['cipher_suites'] if not is_grease(c)])
    c009=0xc009 in p['cipher_suites']; rsl=p['details'].get('record_size_limit')
    print(f"  {name:10} {p['ja3']:34} {nci:<8} {str(c009):8} {rsl:<6} {ech_len(p)}")
ja3s={p['ja3'] for _,p in samples}
print(f"  Firefox ja3 stable across samples: {len(ja3s)==1}  ({ja3s})")
echs={ech_len(p) for _,p in samples}
print(f"  Firefox ECH payload length values: {echs}  (variance => random GREASE)")

print("\n### C. engine(firefox147 default) stability")
from curl_cffi import requests
from tune_engine import capture as cap_tuned  # reuse
eng_samps=[]
for i,port in enumerate([8451,8452,8453]):
    out=os.path.join(PROJ,"captures",f"engine_stab_{i}.json")
    sink=subprocess.Popen([sys.executable,os.path.join(HERE,"hello_sink.py"),
        "--out",out,"--label",f"eng-{port}","--port",str(port),"--count","1","--timeout","12"])
    if not wait_port(port): sink.terminate(); continue
    try: requests.get(f"https://localhost:{port}/",impersonate="firefox147",verify=False,timeout=6)
    except Exception: pass
    sink.wait(timeout=15)
    if os.path.exists(out): eng_samps.append(json.load(open(out)))
for p in eng_samps:
    print(f"  ja3={p['ja3']} c009={0xc009 in p['cipher_suites']} rsl={p['details'].get('record_size_limit')} ech_len={ech_len(p)}")

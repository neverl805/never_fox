#!/usr/bin/env python3
"""Build a TUNED engine that matches real Firefox 152 by overriding curl_cffi's
ja3 (to drop the extra 0xc009 cipher) and record_size_limit (0x4001).
Captures the tuned ClientHello on the sink for diffing."""
import json, os, socket, subprocess, sys, time
HERE=os.path.dirname(os.path.abspath(__file__)); PROJ=os.path.dirname(HERE)

def wait_port(port,deadline=6.0):
    t0=time.time()
    while time.time()-t0<deadline:
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=0.5): return True
        except OSError: time.sleep(0.1)
    return False

def capture(ja3,rsl,port,out,label):
    sink=subprocess.Popen([sys.executable,os.path.join(HERE,"hello_sink.py"),
        "--out",out,"--label",label,"--port",str(port),"--count","1","--timeout","15"])
    if not wait_port(port): sink.terminate(); raise RuntimeError("sink not open")
    from curl_cffi import requests
    from curl_cffi.requests import ExtraFingerprints
    try:
        requests.get(f"https://localhost:{port}/",impersonate="firefox147",
            ja3=ja3, extra_fp=ExtraFingerprints(tls_record_size_limit=rsl),
            verify=False,timeout=6)
    except Exception as e:
        pass
    sink.wait(timeout=20)
    return json.load(open(out)) if os.path.exists(out) else None

if __name__=="__main__":
    ff=json.load(open(os.path.join(PROJ,"captures","firefox152_clienthello.json")))
    ja3=ff["ja3_str"]
    print("target FF152 ja3_str:",ja3)
    out=os.path.join(PROJ,"captures","engine_tuned_clienthello.json")
    p=capture(ja3,16385,8445,out,"engine-tuned")
    if p:
        same = p["ja3"]==ff["ja3"]
        print(f"tuned ja3={p['ja3']}  (FF152 ja3={ff['ja3']})  -> {'✅ MATCH' if same else '❌ still differ'}")
        print(f"tuned ja4={p['ja4']}  (FF152 ja4={ff['ja4']})")
        print(f"-> {out}")

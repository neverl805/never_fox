#!/usr/bin/env python3
"""
Drive the curl_cffi (real-NSS) Firefox engine:
  1. capture its ClientHello on the local sink (same parser as real Firefox)
  2. fetch tls.peet.ws/api/all to record its full fingerprint
     (JA3/JA4 + HTTP/2 Akamai + header order) for the HTTP/2 / header comparison.
"""
import argparse, json, os, socket, subprocess, sys, time
HERE=os.path.dirname(os.path.abspath(__file__))
PROJ=os.path.dirname(HERE)

def wait_port(port,host="127.0.0.1",deadline=6.0):
    t0=time.time()
    while time.time()-t0<deadline:
        try:
            with socket.create_connection((host,port),timeout=0.5): return True
        except OSError: time.sleep(0.1)
    return False

def capture_hello(target,port,out):
    sink=subprocess.Popen([sys.executable,os.path.join(HERE,"hello_sink.py"),
        "--out",out,"--label",f"engine-{target}","--port",str(port),
        "--count","1","--timeout","15"])
    if not wait_port(port):
        sink.terminate(); raise RuntimeError("sink did not open")
    from curl_cffi import requests
    try:
        requests.get(f"https://localhost:{port}/",impersonate=target,
                     verify=False,timeout=6)
    except Exception:
        pass  # sink closes after reading CH -> TLS error is expected
    sink.wait(timeout=20)
    return json.load(open(out)) if os.path.exists(out) else None

def fetch_peet(target,out):
    from curl_cffi import requests
    try:
        r=requests.get("https://tls.peet.ws/api/all",impersonate=target,timeout=20)
        data=r.json(); json.dump(data,open(out,"w"),indent=2)
        return data
    except Exception as e:
        print("peet fetch failed:",e); return None

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--target",default="firefox147")
    ap.add_argument("--port",type=int,default=8443)
    a=ap.parse_args()
    cap_out=os.path.join(PROJ,"captures",f"engine_{a.target}_clienthello.json")
    peet_out=os.path.join(PROJ,"captures",f"engine_{a.target}_peet.json")
    print(f"== capturing engine ClientHello ({a.target}) ==")
    ch=capture_hello(a.target,a.port,cap_out)
    if ch: print(f"  ja3={ch['ja3']}\n  ja4={ch['ja4']}\n  -> {cap_out}")
    else:  print("  FAILED to capture engine ClientHello")
    print(f"== fetching peet.ws fingerprint ({a.target}) ==")
    pj=fetch_peet(a.target,peet_out)
    if pj:
        tls=pj.get("tls",{}); h2=pj.get("http2",{})
        print(f"  peet ja3={tls.get('ja3_hash')}  ja4={tls.get('ja4')}")
        print(f"  akamai_h2={h2.get('akamai_fingerprint_hash') or h2.get('akamai_fingerprint')}")
        print(f"  -> {peet_out}")

if __name__=="__main__":
    main()

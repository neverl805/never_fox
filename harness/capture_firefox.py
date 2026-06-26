#!/usr/bin/env python3
"""Capture REAL Firefox's ClientHello via the local sink (same parser as engine).
Launches Firefox at https://localhost:PORT/ ; Firefox sends its genuine NSS
ClientHello (cleartext, before cert validation) which the sink records."""
import json, os, socket, subprocess, sys, time
HERE=os.path.dirname(os.path.abspath(__file__)); PROJ=os.path.dirname(HERE)
PORT=int(sys.argv[1]) if len(sys.argv)>1 else 8444
OUT=os.path.join(PROJ,"captures","firefox152_clienthello.json")
FF="/Applications/Firefox.app/Contents/MacOS/firefox"

def wait_port(port,deadline=6.0):
    t0=time.time()
    while time.time()-t0<deadline:
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=0.5): return True
        except OSError: time.sleep(0.1)
    return False

sink=subprocess.Popen([sys.executable,os.path.join(HERE,"hello_sink.py"),
    "--out",OUT,"--label","firefox152","--port",str(PORT),"--count","1","--timeout","35"])
if not wait_port(PORT):
    sink.terminate(); sys.exit("sink did not open")
# fresh URL avoids TLS session resumption -> we get the full initial ClientHello
url=f"https://localhost:{PORT}/ff-fp-probe"
print(f"launching Firefox -> {url}")
subprocess.run(["open","-a","Firefox",url])
sink.wait(timeout=40)
if os.path.exists(OUT):
    p=json.load(open(OUT))
    print(f"OK ja3={p['ja3']}\n   ja4={p['ja4']}\n   bytes={len(p['raw_hex'])//2}  -> {OUT}")
else:
    print("FAILED: no ClientHello captured from Firefox")
    sys.exit(2)

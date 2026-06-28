#!/usr/bin/env python3
"""Stage the built native library into the package for wheel-building:
copy native/libfxtls.* + native/vendor/* -> never_fox/_lib/ (+ _lib/vendor/),
preserving the relative layout so @loader_path/$ORIGIN/add_dll_directory still
resolve the vendored NSS libs after `pip install`.
"""
import os, glob, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DST = os.path.join(ROOT, "never_fox", "_lib")


def main():
    shutil.rmtree(DST, ignore_errors=True)
    os.makedirs(os.path.join(DST, "vendor"), exist_ok=True)

    libs = [f for f in glob.glob(os.path.join(HERE, "libfxtls.*")) if not f.endswith(".dSYM")]
    if not libs:
        raise SystemExit("no native/libfxtls.* — run native/build.py first")
    for f in libs:
        shutil.copy2(f, DST)
    n = 0
    for f in glob.glob(os.path.join(HERE, "vendor", "*")):
        if os.path.isfile(f):
            shutil.copy2(f, os.path.join(DST, "vendor")); n += 1

    # h3: bundle the prebuilt Firefox-aligned neqo-client (built by native/h3/build_h3.py)
    # if present. It links the bundled NSS at runtime (h3.py sets the library path), so
    # no extra vendoring is needed. Absent on platforms where h3 isn't built (e.g.
    # Windows) — h3.py then reports unavailable and the client falls back to HTTP/2.
    h3 = 0
    for nq in ("neqo-client", "neqo-client.exe"):
        src = os.path.join(ROOT, "native", "h3", nq)
        if os.path.isfile(src):
            dst = os.path.join(DST, nq)
            shutil.copy2(src, dst)
            os.chmod(dst, 0o755)
            h3 += 1
    print(f"staged {len(libs)} lib(s) + {n} vendored dep(s) + {h3} h3 backend -> {DST}")


if __name__ == "__main__":
    main()

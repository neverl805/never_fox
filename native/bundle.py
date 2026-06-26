#!/usr/bin/env python3
"""Make the engine self-contained: vendor every NSS/NSPR/brotli/zstd dependency
into native/vendor/ so it runs on another machine of the SAME OS+arch without the
package manager. (Cross-OS/arch needs a recompile there — native code.)

  macOS   : copy dylibs + rewrite install names to @loader_path (+ ad-hoc codesign)
  Linux   : copy .so set + patchelf --set-rpath '$ORIGIN'
  Windows : copy the DLLs (resolved at load via os.add_dll_directory)

NSS loads softokn/freebl/ckbi at RUNTIME (not as link deps), so we copy the whole
NSS lib set, not just what otool/ldd report.
"""
import os, re, sys, glob, shutil, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.join(HERE, "vendor")
PLAT = sys.platform
IS_WIN = os.name == "nt"

# NSS/NSPR/brotli/zstd library basenames (without lib prefix / extension)
NSS_LIBS = ["nss3", "nssutil3", "ssl3", "smime3", "softokn3", "freebl3",
            "freeblpriv3", "nssckbi", "nssdbm3", "nspr4", "plc4", "plds4",
            "brotlidec", "brotlicommon", "zstd"]


def sh(*a):
    return subprocess.run(a, capture_output=True, text=True)


def pkg_libdir(mod):
    r = sh("pkg-config", "--variable=libdir", mod)
    return r.stdout.strip() or None


# ---------------- macOS ----------------
def _bundle_macos():
    MAIN = os.path.join(HERE, "libfxtls.dylib")
    SYS = ("/usr/lib/", "/System/")
    if not os.path.exists(MAIN):
        sys.exit("build libfxtls.dylib first (python native/build.py)")
    shutil.rmtree(VENDOR, ignore_errors=True); os.makedirs(VENDOR)
    pref = lambda p: sh("brew", "--prefix", p).stdout.strip()
    src = {pref("nss") + "/lib": "*.dylib", pref("nspr") + "/lib": "libns*.dylib libpl*.dylib",
           pref("brotli") + "/lib": "libbrotli*.dylib", pref("zstd") + "/lib": "libzstd*.dylib"}
    copied = set()
    for d, pats in src.items():
        for pat in pats.split():
            for s in glob.glob(os.path.join(d, pat)):
                b = os.path.basename(s)
                if b not in copied:
                    sh("cp", "-L", s, os.path.join(VENDOR, b)); os.chmod(os.path.join(VENDOR, b), 0o755)
                    copied.add(b)

    def deps(lib):
        return [m.group(1) for m in (re.match(r"\s+(\S+)\s+\(", l)
                for l in sh("otool", "-L", lib).stdout.splitlines()[1:]) if m]
    ext = lambda p: not p.startswith("@") and not p.startswith(SYS)
    for dep in deps(MAIN):
        if ext(dep) and os.path.basename(dep) != "libfxtls.dylib":
            sh("install_name_tool", "-change", dep, f"@loader_path/vendor/{os.path.basename(dep)}", MAIN)
    for b in copied:
        lib = os.path.join(VENDOR, b)
        sh("install_name_tool", "-id", f"@loader_path/{b}", lib)
        for dep in deps(lib):
            if ext(dep):
                sh("install_name_tool", "-change", dep, f"@loader_path/{os.path.basename(dep)}", lib)
    for b in list(copied) + ["../libfxtls.dylib"]:
        sh("codesign", "--force", "--sign", "-", os.path.join(VENDOR, b))
    print(f"OK macOS: vendored {len(copied)} dylibs (@loader_path)")


# ---------------- Linux ----------------
def _bundle_linux():
    if not shutil.which("patchelf"):
        sys.exit("need patchelf (apt-get install patchelf)")
    shutil.rmtree(VENDOR, ignore_errors=True); os.makedirs(VENDOR)
    dirs = _lib_dirs()
    copied = _copy_libs(dirs, ".so")
    # --force-rpath sets DT_RPATH (not RUNPATH): NSS dlopens softokn/freebl by bare
    # soname, and RUNPATH is ignored for dlopen — only RPATH applies.
    for f in glob.glob(os.path.join(VENDOR, "*.so*")):
        sh("patchelf", "--force-rpath", "--set-rpath", "$ORIGIN", f)
    main = os.path.join(HERE, "libfxtls.so")
    sh("patchelf", "--force-rpath", "--set-rpath", "$ORIGIN/vendor:$ORIGIN", main)
    print(f"OK linux: vendored {copied} .so files ($ORIGIN)")


# ---------------- Windows ----------------
def _bundle_windows():
    shutil.rmtree(VENDOR, ignore_errors=True); os.makedirs(VENDOR)
    # DLLs live in the mingw bin dir (sibling of libdir)
    dirs = set()
    for d in _lib_dirs():
        dirs.add(d); dirs.add(os.path.join(os.path.dirname(d), "bin"))
    copied = _copy_libs(dirs, ".dll", extra=["libgcc_s_seh-1", "libwinpthread-1", "zlib1", "libsqlite3-0"])
    print(f"OK windows: vendored {copied} DLLs (os.add_dll_directory)")


def _lib_dirs():
    dirs = set()
    dist = os.environ.get("FXTLS_NSS_DIST")          # built-from-source NSS
    if dist:
        for root, _d, files in os.walk(dist):
            if any(f.startswith("libnss3.so") for f in files):
                dirs.add(root)
    for mod in ("nss", "nspr", "libbrotlidec", "libzstd"):
        d = pkg_libdir(mod)
        if d and os.path.isdir(d):
            dirs.add(d)
            if os.path.isdir(os.path.join(d, "nss")):
                dirs.add(os.path.join(d, "nss"))
    if not dist:                  # only scan system dirs when NOT using from-source NSS
        for d in ("/usr/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu/nss",
                  "/usr/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu/nss", "/usr/lib64"):
            if os.path.isdir(d):
                dirs.add(d)
    return dirs


def _copy_libs(dirs, ext, extra=()):
    names = NSS_LIBS + list(extra)
    n = 0
    for d in dirs:
        for f in glob.glob(os.path.join(d, "*" + ext + "*")):
            base = os.path.basename(f)
            if any(base.startswith(("lib" + x, x)) and (x in base) for x in names):
                dst = os.path.join(VENDOR, base)
                if not os.path.exists(dst):
                    shutil.copy2(os.path.realpath(f), dst); n += 1
    return n


def main():
    if PLAT == "darwin":
        _bundle_macos()
    elif IS_WIN:
        _bundle_windows()
    else:
        _bundle_linux()


if __name__ == "__main__":
    main()

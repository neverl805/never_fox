#!/usr/bin/env python3
"""Cross-platform build for the native engine (libfxtls).

Finds NSS/NSPR/brotli/zstd via pkg-config (Homebrew on macOS, apt on Linux,
MSYS2 mingw on Windows), then compiles fxtls_lib.c into a shared library:
  macOS   -> libfxtls.dylib
  Linux   -> libfxtls.so
  Windows -> libfxtls.dll   (MSYS2/mingw toolchain)

NSS itself is never compiled here — it comes prebuilt from the package manager.
Only this ~250-line engine compiles (seconds).
"""
import os, sys, subprocess, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
PLAT = sys.platform                      # 'darwin' | 'linux' | 'win32'/'msys'
IS_WIN = PLAT.startswith("win") or PLAT == "msys" or os.name == "nt"
EXT = "dylib" if PLAT == "darwin" else "dll" if IS_WIN else "so"
OUT = os.path.join(HERE, f"libfxtls.{EXT}")


def pkg(mod, *flags):
    """pkg-config flags for `mod`, or [] if unavailable."""
    if not shutil.which("pkg-config"):
        return []
    try:
        return subprocess.check_output(["pkg-config", *flags, mod], text=True).split()
    except Exception:
        return []


def main():
    cc = os.environ.get("CC") or ("clang" if PLAT == "darwin" else "gcc" if IS_WIN else "cc")

    dist = os.environ.get("FXTLS_NSS_DIST")          # built-from-source NSS (self-consistent)
    if dist:
        cflags, libs = _nss_from_dist(dist)
    else:
        cflags = pkg("nss", "--cflags") or _fallback_cflags()
        libs = pkg("nss", "--libs") or _fallback_libs()
    # brotli + zstd (+ system zlib)
    for mod, brew, lflag in (("libbrotlidec", "brotli", "-lbrotlidec"),
                             ("libzstd", "zstd", "-lzstd")):
        pc_c, pc_l = pkg(mod, "--cflags"), pkg(mod, "--libs")
        if pc_c or pc_l:
            cflags += [f for f in pc_c if f.startswith("-I")]
            libs += [f for f in pc_l if f.startswith(("-L", "-l"))]
        else:
            prefix = _brew_prefix(brew)
            if prefix:
                cflags.append("-I" + os.path.join(prefix, "include"))
                libs += ["-L" + os.path.join(prefix, "lib"), lflag]
            else:
                libs.append(lflag)          # standard system paths (apt / mingw)
    libs.append("-lz")
    if not (PLAT == "darwin" or IS_WIN):
        libs.append("-ldl")                      # dladdr (no-op on glibc>=2.34)

    if PLAT == "darwin":
        shared = ["-dynamiclib", "-install_name", OUT]
        rpaths = [f"-Wl,-rpath,{p}" for p in _libdirs(libs)]
    elif IS_WIN:
        shared = ["-shared"]
        rpaths = []                                  # Windows: DLLs resolved at load via add_dll_directory
    else:
        shared = ["-shared", "-fPIC"]
        rpaths = ["-Wl,-rpath,$ORIGIN/vendor", "-Wl,-rpath,$ORIGIN",
                  *[f"-Wl,-rpath,{p}" for p in _libdirs(libs)], "-Wl,-z,origin"]

    cmd = [cc, "-O2", "-g", *shared, "-o", OUT, os.path.join(HERE, "fxtls_lib.c"),
           *cflags, *libs, *rpaths]
    print(" ".join(cmd))
    subprocess.run(cmd, check=True)
    print(f"built {OUT}")


def _libdirs(libs):
    return [f[2:] for f in libs if f.startswith("-L")]


def nss_lib_dir(dist):
    """Find the dir under a from-source NSS dist that holds libssl3.so."""
    for root, _dirs, files in os.walk(dist):
        if any(f.startswith("libssl3.so") for f in files):
            return root
    return os.path.join(dist, "lib")


def _nss_from_dist(dist):
    incs = set()
    for root, _dirs, files in os.walk(dist):
        if {"ssl.h", "prinit.h", "nss.h"} & set(files):
            incs.add(root)
    libdir = nss_lib_dir(dist)
    cflags = ["-I" + d for d in sorted(incs)]
    # link only the core libs; softokn/freebl/ckbi are dlopen'd by NSS at runtime
    libs = ["-L" + libdir, "-lssl3", "-lsmime3", "-lnss3", "-lnssutil3",
            "-lnspr4", "-lplc4", "-lplds4"]
    return cflags, libs


def _brew_prefix(name):
    if PLAT == "darwin" and shutil.which("brew"):
        try:
            return subprocess.check_output(["brew", "--prefix", name], text=True).strip()
        except Exception:
            return None
    return None


def _fallback_cflags():
    # macOS Homebrew layout if pkg-config missed nss
    out = []
    for p in ("/opt/homebrew/opt/nss/include/nss", "/opt/homebrew/opt/nspr/include/nspr",
              "/usr/include/nss", "/usr/include/nspr"):
        if os.path.isdir(p):
            out.append("-I" + p)
    return out


def _fallback_libs():
    out = []
    for p in ("/opt/homebrew/opt/nss/lib", "/opt/homebrew/opt/nspr/lib"):
        if os.path.isdir(p):
            out.append("-L" + p)
    return out + ["-lssl3", "-lnss3", "-lnssutil3", "-lsmime3", "-lnspr4", "-lplc4", "-lplds4"]


if __name__ == "__main__":
    main()

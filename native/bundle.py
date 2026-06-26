#!/usr/bin/env python3
"""Make libfxtls.dylib self-contained: vendor every non-system dependency into
native/vendor/ and rewrite load paths to @loader_path, so the package runs on
another machine of the SAME OS+arch without Homebrew.

(Cross-OS / cross-arch still needs a recompile there — native code, like Cronet's
per-platform binaries.)
"""
import os, re, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.join(HERE, "vendor")
MAIN = os.path.join(HERE, "libfxtls.dylib")
SYS_PREFIXES = ("/usr/lib/", "/System/")     # always present on macOS -> leave as-is


def sh(*a):
    return subprocess.run(a, capture_output=True, text=True)

def brew_prefix(p):
    return sh("brew", "--prefix", p).stdout.strip()

def deps(lib):
    out = sh("otool", "-L", lib).stdout.splitlines()[1:]
    res = []
    for line in out:
        m = re.match(r"\s+(\S+)\s+\(", line)
        if m:
            res.append(m.group(1))
    return res


def main():
    if not os.path.exists(MAIN):
        sys.exit("build libfxtls.dylib first (bash native/build.sh)")
    shutil.rmtree(VENDOR, ignore_errors=True)
    os.makedirs(VENDOR)

    nss, nspr = brew_prefix("nss"), brew_prefix("nspr")
    brotli, zstd = brew_prefix("brotli"), brew_prefix("zstd")

    # Sources to vendor. NSS loads softokn/freebl/ckbi at RUNTIME (not via otool
    # link deps), so copy the whole nss lib dir to be safe.
    src_dirs = {
        nss + "/lib":  "*.dylib",
        nspr + "/lib": "libnspr4.dylib libplc4.dylib libplds4.dylib",
        brotli + "/lib": "libbrotli*.dylib",
        zstd + "/lib":  "libzstd*.dylib",
    }
    import glob
    copied = set()
    for d, pats in src_dirs.items():
        for pat in pats.split():
            for src in glob.glob(os.path.join(d, pat)):
                base = os.path.basename(src)
                dst = os.path.join(VENDOR, base)
                if base in copied:
                    continue
                # cp -L dereferences symlinks -> real file under the referenced name
                sh("cp", "-L", src, dst)
                os.chmod(dst, 0o755)
                copied.add(base)
    print(f"vendored {len(copied)} dylibs into {VENDOR}")

    def is_external(p):
        return not p.startswith("@") and not p.startswith(SYS_PREFIXES)

    # rewrite the main lib: external deps -> @loader_path/vendor/<base>
    for dep in deps(MAIN):
        if is_external(dep) and os.path.basename(dep) != "libfxtls.dylib":
            sh("install_name_tool", "-change", dep,
               f"@loader_path/vendor/{os.path.basename(dep)}", MAIN)

    # rewrite every vendored lib: id + sibling deps -> @loader_path/<base>
    for base in copied:
        lib = os.path.join(VENDOR, base)
        sh("install_name_tool", "-id", f"@loader_path/{base}", lib)
        for dep in deps(lib):
            if is_external(dep):
                sh("install_name_tool", "-change", dep,
                   f"@loader_path/{os.path.basename(dep)}", lib)

    # re-sign (ad-hoc) — modifying load commands invalidates signatures on arm64
    for base in copied:
        sh("codesign", "--force", "--sign", "-", os.path.join(VENDOR, base))
    sh("codesign", "--force", "--sign", "-", MAIN)

    # verify nothing external remains
    bad = []
    for lib in [MAIN] + [os.path.join(VENDOR, b) for b in copied]:
        for dep in deps(lib):
            if is_external(dep) and os.path.basename(dep) != os.path.basename(lib):
                bad.append((os.path.basename(lib), dep))
    if bad:
        print("WARNING: external deps remain:")
        for l, d in bad[:20]:
            print(f"  {l} -> {d}")
    else:
        print("OK: fully self-contained (only @loader_path + /usr/lib remain)")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Build the Firefox-152-aligned `neqo-client` — never_fox's HTTP/3 backend.

Clones the pinned mozilla/neqo + mozilla/nss-rs, overlays never_fox's patched
files (native/h3/files/), wires a Cargo `[patch]` so neqo links the patched
nss-rs, then builds `neqo-client`.

The patched nss-rs adds ffdhe2048/3072 groups, the delegated_credentials option,
an `SSL_SignatureSchemePrefSet` binding (+ `set_signature_schemes`) and RFC 8879
certificate (de)compression (zlib/brotli/zstd). The patched `crypto.rs` makes the
QUIC ClientHello match Firefox 152: GREASE off, fixed extension order, SCT, ECH
GREASE, Firefox signature-algorithm order, certificate compression.

Build deps (installed by CI / a setup script, not here): rustup+cargo, a C/C++
toolchain, libclang (set LIBCLANG_PATH on Linux), and — because nss-rs compiles
NSS from source — mercurial + ninja + gyp-next.

Env knobs:
  H3_WORK     work dir for the clones+build (default: native/h3/build)
  H3_OUT      where to copy the resulting binary (default: native/h3/neqo-client)
  H3_NSS_DIR  reuse a prebuilt NSS source dir (sets NSS_PREBUILT=1) to skip the
              heavy from-source NSS build on repeat runs
"""
import os
import shutil
import subprocess
from pathlib import Path

NEQO_URL = "https://github.com/mozilla/neqo.git"
NEQO_REV = "c1462a77312105ca2dc50f1fdecf8e97107c7bb3"
NSS_RS_URL = "https://github.com/mozilla/nss-rs.git"
NSS_RS_REV = "da11b438"  # matches neqo's Cargo.lock

HERE = Path(__file__).resolve().parent
FILES = HERE / "files"


def run(cmd, cwd=None, env=None):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def clone(url, rev, dest):
    if (dest / ".git").exists():
        print(f"reuse {dest}", flush=True)
        return
    run(["git", "clone", url, str(dest)])
    run(["git", "checkout", rev], cwd=dest)


def overlay(src_root, dst_root):
    for f in src_root.rglob("*"):
        if f.is_file():
            rel = f.relative_to(src_root)
            (dst_root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dst_root / rel)
            print(f"overlay {rel}", flush=True)


def main():
    work = Path(os.environ.get("H3_WORK", HERE / "build")).resolve()
    work.mkdir(parents=True, exist_ok=True)
    neqo, nss_rs = work / "neqo", work / "nss-rs"

    clone(NEQO_URL, NEQO_REV, neqo)
    clone(NSS_RS_URL, NSS_RS_REV, nss_rs)
    overlay(FILES / "neqo", neqo)
    overlay(FILES / "nss-rs", nss_rs)

    cargo = neqo / "Cargo.toml"
    txt = cargo.read_text()
    if 'patch."https://github.com/mozilla/nss-rs"' not in txt:
        txt += ('\n[patch."https://github.com/mozilla/nss-rs"]\n'
                f'nss-rs = {{ path = "{nss_rs.as_posix()}" }}\n')
        cargo.write_text(txt)
        print("added [patch] -> patched nss-rs", flush=True)

    env = dict(os.environ)
    env.setdefault("CARGO_BUILD_JOBS", "2")
    if os.environ.get("H3_NSS_DIR"):
        env["NSS_DIR"] = os.environ["H3_NSS_DIR"]
        env["NSS_PREBUILT"] = "1"

    # not --locked: the [patch] intentionally updates the lock file
    run(["cargo", "build", "--release", "--bin", "neqo-client"], cwd=neqo, env=env)

    exe = "neqo-client.exe" if os.name == "nt" else "neqo-client"
    out = Path(os.environ.get("H3_OUT", HERE / exe)).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(neqo / "target" / "release" / exe, out)
    os.chmod(out, 0o755)
    print("\nNEQO_CLIENT:", out, flush=True)


if __name__ == "__main__":
    main()

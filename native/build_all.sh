#!/bin/sh
# Build the vcdidx cdylib for every distribution target into native/dist/.
# Linux uses gnu targets with glibc pinned to 2.17 via cargo-zigbuild —
# the floor that covers CentOS 7 and every mainstream distro since (musl
# cannot be used: rustc drops cdylib for musl targets). Windows uses MinGW
# (no vcruntime dependency); macOS links through zig's bundled SDK stubs.
#
# Toolchain (pinned so local builds match the CI `native` job): Rust from
# rust-toolchain.toml (rustup installs it and the targets on first use),
# zig $ZIG_VERSION (`pip install ziglang==$ZIG_VERSION`), cargo-zigbuild
# $ZIGBUILD_VERSION (`pip install cargo-zigbuild==$ZIGBUILD_VERSION`).
# cargo-zigbuild may run the pip ziglang (`python3 -m ziglang`) rather than
# a `zig` on PATH, so both are checked.
#
# The libraries embedded in vcd_analyzer.py are the CI build: download the
# `native-dist` artifact of the CI `native` job into native/dist/ and run
# `python _make.py`. Local builds with the pinned toolchain match it byte
# for byte on Linux and Windows; the macOS library differs in its LC_UUID
# (and the ad-hoc signature hashes over it), which zig's linker derives
# from machine-specific input paths.
set -e
ZIG_VERSION=0.16.0
ZIGBUILD_VERSION=0.24.0
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"
for zig_found in "$(zig version 2>/dev/null)" "$(python3 -m ziglang version 2>/dev/null)"; do
  if [ -n "$zig_found" ] && [ "$zig_found" != "$ZIG_VERSION" ]; then
    echo "warning: zig $zig_found found, $ZIG_VERSION pinned — the libraries will not match CI" >&2
  fi
done
zigbuild_found=$(cargo-zigbuild --version 2>/dev/null | awk '{print $2}')
if [ "$zigbuild_found" != "$ZIGBUILD_VERSION" ]; then
  echo "warning: cargo-zigbuild ${zigbuild_found:-none} found, $ZIGBUILD_VERSION pinned" >&2
fi
TARGETS="aarch64-unknown-linux-gnu.2.17 x86_64-unknown-linux-gnu.2.17 x86_64-pc-windows-gnu aarch64-apple-darwin"
for t in $TARGETS; do
  echo "== $t =="
  cargo zigbuild --locked --release --target "$t"
done
mkdir -p dist
cp target/aarch64-unknown-linux-gnu/release/libvcdidx.so   dist/aarch64-linux.so
cp target/x86_64-unknown-linux-gnu/release/libvcdidx.so    dist/x86_64-linux.so
cp target/x86_64-pc-windows-gnu/release/vcdidx.dll         dist/x86_64-windows.dll
cp target/aarch64-apple-darwin/release/libvcdidx.dylib     dist/aarch64-macos.dylib
# The PE header carries the link time (zig's linker has no switch to omit
# it); zero it so rebuilds are byte-identical. Windows does not use it.
python3 - dist/x86_64-windows.dll <<'PY'
import struct, sys
path = sys.argv[1]
data = bytearray(open(path, 'rb').read())
pe = struct.unpack_from('<I', data, 0x3c)[0]
assert data[pe:pe + 4] == b'PE\0\0', 'not a PE image'
struct.pack_into('<I', data, pe + 8, 0)  # COFF TimeDateStamp
open(path, 'wb').write(data)
PY
# sanity: the ABI entry points must be present in each artifact
for f in dist/*; do
  if strings "$f" | grep -q vcdidx_abi_build; then
    echo "ok  $f ($(wc -c < "$f" | tr -d ' ') bytes)"
  else
    echo "MISSING ABI SYMBOL in $f"; exit 1
  fi
done

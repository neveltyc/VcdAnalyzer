#!/bin/sh
# Build the vcdidx cdylib for every distribution target into native/dist/.
# Linux uses gnu targets with glibc pinned to 2.17 via cargo-zigbuild —
# the floor that covers CentOS 7 and every mainstream distro since (musl
# cannot be used: rustc drops cdylib for musl targets). Windows uses MinGW
# (no vcruntime dependency); macOS uses the Apple SDK through zig cc.
# Requires: cargo, cargo-zigbuild, zig, and the rustup targets below.
set -e
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"
TARGETS="aarch64-unknown-linux-gnu.2.17 x86_64-unknown-linux-gnu.2.17 x86_64-pc-windows-gnu aarch64-apple-darwin"
for t in $TARGETS; do
  echo "== $t =="
  cargo zigbuild --release --target "$t"
done
mkdir -p dist
cp target/aarch64-unknown-linux-gnu/release/libvcdidx.so   dist/aarch64-linux.so
cp target/x86_64-unknown-linux-gnu/release/libvcdidx.so    dist/x86_64-linux.so
cp target/x86_64-pc-windows-gnu/release/vcdidx.dll         dist/x86_64-windows.dll
cp target/aarch64-apple-darwin/release/libvcdidx.dylib     dist/aarch64-macos.dylib
# sanity: the ABI entry points must be present in each artifact
for f in dist/*; do
  if nm -D "$f" 2>/dev/null | grep -q vcdidx_abi_build || nm "$f" 2>/dev/null | grep -q vcdidx_abi_build || strings "$f" | grep -q vcdidx_abi_build; then
    echo "ok  $f ($(stat -f %z "$f" 2>/dev/null || stat -c %s "$f") bytes)"
  else
    echo "MISSING ABI SYMBOL in $f"; exit 1
  fi
done

#!/usr/bin/env bash
set -Eeuo pipefail
NAME=mcpwall
PREFIX=${PREFIX:-"$HOME/.local"}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if command -v cargo >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/Cargo.toml" ]; then
  cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml"
  install -d "$PREFIX/bin"
  install -m 0755 "$SCRIPT_DIR/target/release/$NAME" "$PREFIX/bin/$NAME"
else
  OS_LC=$(uname -s | tr '[:upper:]' '[:lower:]')
  ARCH=$(uname -m)
  if [ "$OS_LC" != linux ] || [ "$ARCH" != x86_64 ]; then
    printf 'no verified prebuilt artifact for %s/%s; build from source with Rust\n' "$OS_LC" "$ARCH" >&2
    exit 1
  fi
  BASE=${RELEASE_BASE:-https://github.com/Hardonian/mcpwall/releases/latest/download}
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT
  asset="$NAME-linux-x86_64-gnu"
  curl -fsSL "$BASE/$asset" -o "$tmpdir/$asset"
  curl -fsSL "$BASE/RELEASE-MANIFEST.json" -o "$tmpdir/RELEASE-MANIFEST.json"
  curl -fsSL "$BASE/SHA256SUMS" -o "$tmpdir/SHA256SUMS"
  (cd "$tmpdir" && sha256sum -c SHA256SUMS)
  install -d "$PREFIX/bin"
  install -m 0755 "$tmpdir/$asset" "$PREFIX/bin/$NAME"
fi
"$PREFIX/bin/$NAME" --help
printf 'installed %s to %s/bin/%s\n' "$NAME" "$PREFIX" "$NAME"

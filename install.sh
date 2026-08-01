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
  BASE=${RELEASE_BASE:-https://github.com/Hardonian/mcpwall/releases/latest/download}
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  curl -fsSL "$BASE/$NAME-$OS_LC-$ARCH-static" -o "$tmp"
  chmod +x "$tmp"
  install -d "$PREFIX/bin"
  install -m 0755 "$tmp" "$PREFIX/bin/$NAME"
fi
"$PREFIX/bin/$NAME" --help
printf 'installed %s to %s/bin/%s\n' "$NAME" "$PREFIX" "$NAME"

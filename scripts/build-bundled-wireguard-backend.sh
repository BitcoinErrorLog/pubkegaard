#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAURI_DIR="$ROOT/apps/pubkegaard-desktop/src-tauri"
BIN_DIR="$TAURI_DIR/binaries"
TARGET_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
SIDEcar="$BIN_DIR/boringtun-cli-$TARGET_TRIPLE"

mkdir -p "$BIN_DIR"

if [[ -x "$SIDEcar" ]]; then
  echo "ok: bundled WireGuard backend exists at $SIDEcar"
  exit 0
fi

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT

cargo install boringtun-cli --root "$TMP_ROOT"
cp "$TMP_ROOT/bin/boringtun-cli" "$SIDEcar"
chmod 755 "$SIDEcar"

echo "ok: built bundled WireGuard backend at $SIDEcar"

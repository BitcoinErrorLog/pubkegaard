#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DMG="$ROOT/releases/Pubkegaard_0.1.0_aarch64.dmg"
BACKEND="$ROOT/apps/pubkegaard-desktop/src-tauri/binaries/boringtun-cli-aarch64-apple-darwin"

echo "Pubkegaard macOS two-peer preflight"
echo "repo: $ROOT"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: this preflight is for macOS" >&2
  exit 1
fi

if [[ ! -x "$BACKEND" ]]; then
  echo "error: missing bundled WireGuard backend at $BACKEND" >&2
  echo "run: ./scripts/build-bundled-wireguard-backend.sh" >&2
  exit 1
fi

if [[ ! -f "$DMG" ]]; then
  echo "error: missing DMG at $DMG" >&2
  exit 1
fi

hdiutil verify "$DMG" >/dev/null

echo "ok: bundled WireGuard backend is present"
echo "ok: DMG verifies"
echo
echo "Two-peer validation:"
echo "1. Run this preflight on both Macs."
echo "2. Install Pubkegaard from $DMG on both Macs."
echo "3. Create local keys on both Macs."
echo "4. Configure homeserver URL + session token on both Macs."
echo "5. Publish discovery + PKARR pointer on both Macs."
echo "6. Add each peer by Pubky identity."
echo "7. Apply WireGuard on both Macs and ping the peer overlay address."

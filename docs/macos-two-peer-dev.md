# macOS Two Peer Dev Setup

This is the first working Pubkegaard desktop path. It uses installed WireGuard tooling on macOS and produces a development DMG through Tauri.

## Prerequisites

Each Mac needs:

```sh
brew install wireguard-tools
```

The app uses `wg-quick` through a macOS administrator prompt when applying or stopping the tunnel.

## Build The DMG

From the repository root:

```sh
cd apps/pubkegaard-desktop
npm install
npm run build
npm run tauri build -- --bundles dmg
```

The checked build artifact for this pass is `releases/Pubkegaard_0.1.0_aarch64.dmg`.

## Pair Two Macs

On both Macs:

1. Open Pubkegaard.
2. Choose **Create local Pubkegaard keys**.
3. Go to **Peers**.
4. Enter an advertised endpoint host or IP if the other peer should initiate to this Mac.
5. Click **Export profile**.
6. Send the exported JSON to the other peer.

Then on each Mac:

1. Paste the other peer's JSON profile in **Add peer profile**.
2. Choose **Private mesh only**.
3. Click **Import peer**.
4. Go to **Network**.
5. Click **Apply WireGuard tunnel**.
6. Approve the macOS administrator prompt.

After both sides apply, each peer should be reachable at the overlay address shown in the dashboard.

## Stop Or Revoke

- **Stop WireGuard** runs `wg-quick down` for the Pubkegaard config.
- **Revoke** removes the peer from local state; apply the tunnel again to rewrite WireGuard without that peer.
- **Emergency stop** stops WireGuard and marks risky peer modes stopped.

## Current Boundary

This path is real WireGuard config and real OS-level application through `wg-quick`. Pubky homeserver publishing and PKARR-bound `pubky-noise` discovery are still separate integration work; this dev flow uses explicit profile exchange so two users can peer now.

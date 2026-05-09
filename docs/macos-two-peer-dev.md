# macOS Two Peer Dev Setup

This is the first working Pubkegaard desktop path. It publishes discovery through a Pubky homeserver plus signed `_pubkegaard` PKARR pointer, resolves peers by Pubky identity, uses installed WireGuard tooling on macOS, and produces a development DMG through Tauri.

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

## Publish Discovery

On both Macs:

1. Open Pubkegaard.
2. Choose **Create local Pubkegaard keys**.
3. Open **Settings**.
4. Enter a homeserver URL and Pubky session token.
5. Click **Save session**.
6. Click **Publish discovery + PKARR pointer**.
7. Give the other user your Pubky identity from the dashboard.

The app writes `/pub/pubkegaard/v1/discovery.json` to the homeserver, signs a `_pubkegaard` PKARR TXT pointer with the local Pubky root key, and stores the rendered pointer in app state.

## Pair Two Macs By Pubky Identity

On each Mac:

1. Open **Peers**.
2. Paste the other user's Pubky identity into **Add peer by Pubky discovery**.
3. Choose **Private mesh only**.
4. Click **Resolve and add**.
5. Open **Network**.
6. Click **Apply WireGuard tunnel**.
7. Approve the macOS administrator prompt.

After both sides apply, each peer should be reachable at the overlay address shown in the dashboard.

## Manual Profile Fallback

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

Manual JSON exchange remains available if a peer has not published discovery yet.

## Stop Or Revoke

- **Stop WireGuard** runs `wg-quick down` for the Pubkegaard config.
- **Revoke** removes the peer from local state; apply the tunnel again to rewrite WireGuard without that peer.
- **Emergency stop** stops WireGuard and marks risky peer modes stopped.

## Current Boundary

This path is real discovery publishing, real PKARR pointer publishing, real PKARR peer resolution, real WireGuard config, and real OS-level application through `wg-quick`. The current `pubky-noise` control key is carried in the Pubkegaard discovery document; it should move to the upstream `pubky-noise` PKARR binding API once that API lands.

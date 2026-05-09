# Pubkegaard

Pubkegaard is a Pubky-native desktop app and control plane for trusted-peer WireGuard networks.

The current working path is macOS-first: two users can install the development DMG, create local Pubkegaard keys, exchange peer profile JSON, and apply a WireGuard tunnel through installed `wg-quick` tooling. Pubky homeserver publishing and PKARR-bound `pubky-noise` discovery remain the next integration layer; the current dev app uses explicit profile exchange so peers can connect now.

The product launch path remains staged:

1. macOS dev mesh: profile exchange, explicit peer import, WireGuard host routes, revoke, stop, and emergency stop.
2. Linux mesh alpha: explicit Pubky identity whitelist, PKARR discovery, WireGuard host routes, and immediate revocation.
3. Relay beta: authenticated relay fallback for encrypted WireGuard packets when direct UDP is unavailable.
4. Exit gated release: exit client/server mode only after DNS leak protection, kill switch, firewall rollback, and abuse controls are proven.

## Canonicality Rule

Pubkegaard treats implemented Pubky SDK and PKARR behavior as the compatibility baseline. Local crypto, Paykit, Noise, and unified key drafts are useful research context only unless their patterns are present in implemented code or current upstream repositories.

## Workspace

- `docs/spec/` contains the protocol and launch specifications.
- `crates/` contains reusable Rust libraries for types, discovery, policy, keys, platform adapters, WireGuard, and firewall planning.
- `apps/` contains the CLI, desktop app, daemon, and relay binaries.
- `tests/integration/` contains cross-crate launch-path tests.

## Current Transport

WireGuard is the v1 packet transport. Pubky identifies peers, PKARR discovers current documents, and local policy decides what each peer may do.

## macOS Development App

Prerequisite on each Mac:

```sh
brew install wireguard-tools
```

Build the development DMG:

```sh
cd apps/pubkegaard-desktop
npm install
npm run build
npm run tauri build -- --bundles dmg
```

The checked build artifact from the current pass is:

```text
releases/Pubkegaard_0.1.0_aarch64.dmg
```

Two-peer setup:

1. Both users open Pubkegaard and choose **Create local Pubkegaard keys**.
2. Each user exports a peer profile JSON from **Peers**.
3. Each user imports the other profile as **Private mesh only**.
4. Each user opens **Network** and clicks **Apply WireGuard tunnel**.
5. macOS prompts for administrator approval because the app calls `wg-quick`.

See `docs/macos-two-peer-dev.md` for the full setup and stop/revoke flow.

## Current Boundaries

- The macOS app applies real WireGuard config through `wg-quick`; it is not yet notarized or production-signed.
- Pubky root identity keys, `pubky-noise` control keys, and WireGuard keys are generated locally.
- Peer discovery is manual profile exchange for now.
- PKARR-bound `pubky-noise` discovery and Pubky homeserver publication are still pending integration work.
- Relay and exit modes remain gated until their safety requirements are implemented and tested.

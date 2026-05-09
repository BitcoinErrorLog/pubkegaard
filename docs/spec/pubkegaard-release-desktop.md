# Pubkegaard Desktop Release Plan

## Release Tracks

### Mesh Alpha

Mesh Alpha is Linux-first. It requires local key generation, discovery publication, peer grants, WireGuard config generation, Linux route/firewall planning, revoke, and emergency stop.

### Relay Beta

Relay Beta adds relay state and operator controls after authenticated control messages and per-peer relay limits are implemented.

### Exit Gated Release

Exit mode is disabled until DNS leak protection, kill switch behavior, endpoint route preservation, private range blocking, and emergency stop are verified.

## Packaging

### macOS

- Signed `.dmg`.
- Notarization.
- Helper or extension install flow where required.
- Explicit entitlement checklist.

### Windows

- Signed installer.
- WireGuardNT or Wintun install flow.
- Windows Firewall rule rollback.

### Linux

- `.deb`.
- `.rpm`.
- AppImage.
- Optional systemd service install.

## Test Gates

Every release candidate must pass:

- Rust unit and integration tests.
- Desktop UI flow checks for onboarding, add peer, revoke, and emergency stop.
- Linux namespace mesh and revoke tests.
- Manual macOS and Windows setup checklists until adapters are automated.

No public release is allowed while recovery, revoke, and emergency stop are unproven.

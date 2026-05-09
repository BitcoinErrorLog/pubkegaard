# Pubkegaard Platform Networking

## Shared Model

All operating systems expose the same logical operations:

- Install or verify the local networking backend.
- Start the Pubkegaard WireGuard interface.
- Stop the interface.
- Apply peer route updates.
- Apply DNS settings.
- Enable or disable the kill switch.
- Revoke a peer.
- Emergency stop.

The UI calls these operations through `pubkegaardd`. The daemon calls a platform adapter.

## Linux

Linux is the first real adapter.

- Prefer kernel WireGuard.
- Use nftables first.
- Keep firewall rollback actions for every applied peer rule.
- Use network namespace integration tests for mesh and revoke behavior.
- Treat systemd auto-start as optional.

## macOS

macOS support must use APIs compatible with signed distribution.

- Prefer a WireGuard userspace or Network Extension strategy.
- Plan entitlements before release packaging.
- Use a privileged helper only for operations that cannot be done by the app.
- DNS and kill switch behavior must use macOS-supported network APIs.

## Windows

Windows support must use a WireGuardNT or Wintun-compatible adapter.

- Installer asks for administrator approval when driver/helper install is required.
- Windows Firewall rules must be explicit and reversible.
- Named pipes are preferred for local daemon IPC.

## Safety Requirements

Every adapter must support an emergency stop operation before relay server, exit server, LAN sharing, or public release is enabled.

Emergency stop removes risky routes, disables forwarding, restores DNS where possible, removes WireGuard peers, and leaves enough status information for the UI to explain what happened.

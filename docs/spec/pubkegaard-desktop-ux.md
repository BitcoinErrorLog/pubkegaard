# Pubkegaard Desktop UX

## First Run

The first-run flow must make key custody understandable without exposing protocol details first.

1. Explain that Pubkegaard connects trusted Pubky peers over WireGuard.
2. Create or import Pubkegaard identity material when root/binding authority is needed.
3. Generate a local `pubky-noise` control key.
4. Generate a local WireGuard device key.
5. Optionally connect Pubky Ring for homeserver session authorization.
6. Publish the first discovery document.
7. Run the platform network setup wizard.

Session-only mode is allowed, but the UI must warn that PKARR-bound control-key authorization and compact pointer publishing may be unavailable.

## Main Dashboard

The dashboard shows:

- Current Pubky identity.
- Device label and key status.
- Discovery publish status.
- WireGuard interface state.
- Peer count and active tunnels.
- Relay and exit mode status.
- Active safety warnings.

## Peer Management

Adding a peer starts with a Pubky identity string. The app resolves the peer discovery document and shows available devices before any grant is created.

The grant presets are:

- Private mesh only.
- Use peer as relay.
- Let peer relay encrypted packets through me.
- Use peer as VPN exit.
- Let peer use me as VPN exit.
- Share selected LAN routes.

Exit and LAN presets require an additional confirmation screen because they change traffic boundaries.

## Network View

The network view shows per-peer state:

- Resolving.
- Direct.
- Relayed.
- Degraded.
- Stopped.

Each peer row should show the latest WireGuard handshake, endpoint, allowed routes, relay fallback state, and whether the peer is using any risky permission.

## Safety UX

Exit mode must be opt-in and explicit. The UI must distinguish:

- Using a peer as my exit.
- Letting a peer use me as exit.

When exit, relay server, or LAN sharing is active, an emergency stop action must stay visible. Emergency stop revokes risky routes and asks the daemon to remove routes, DNS changes, firewall forwarding, and WireGuard peers.

## Settings

Settings include:

- Identity and key vault.
- Pubky account/session.
- Control key rotation.
- WireGuard key rotation.
- Discovery publish interval.
- Overlay IPv4/IPv6 ranges.
- Relay preferences.
- DNS mode.
- Kill switch.
- Export/import local policy backup.
- Privacy-preserving logs.

## Accessibility

All destructive or risky actions require text labels, not icon-only controls. Status indicators must not rely on color alone.

# Pubkegaard

Pubkegaard is a Pubky-native control plane for trusted-peer WireGuard networks.

The launch path is staged:

1. Linux mesh alpha: explicit Pubky identity whitelist, PKARR discovery, WireGuard host routes, and immediate revocation.
2. Relay beta: authenticated relay fallback for encrypted WireGuard packets when direct UDP is unavailable.
3. Exit gated release: exit client/server mode only after DNS leak protection, kill switch, firewall rollback, and abuse controls are proven.

## Canonicality Rule

Pubkegaard treats implemented Pubky SDK and PKARR behavior as the compatibility baseline. Local crypto, Paykit, Noise, and unified key drafts are useful research context only unless their patterns are present in implemented code or current upstream repositories.

## Workspace

- `docs/spec/` contains the protocol and launch specifications.
- `crates/` contains reusable Rust libraries.
- `apps/` contains the CLI, daemon, and relay binaries.
- `tests/integration/` contains cross-crate launch-path tests.

## Current Transport

WireGuard is the v1 packet transport. Pubky identifies peers, PKARR discovers current documents, and local policy decides what each peer may do.

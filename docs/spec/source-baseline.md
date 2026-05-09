# Source Baseline

This file records the sources Pubkegaard targets for its initial specification and launch implementation.

## Canonical Implementation Sources

These are implemented code paths or public APIs and are the compatibility baseline for Pubkegaard v1.

| Source | Local Path or URL | Revision | Status |
| --- | --- | --- | --- |
| Pubky SDK and homeserver workspace | `/Volumes/vibedrive/vibes-dev/pubky-core` | `5d048d3e24ee1095ca7d223372ab83ac2b5b84ca` | Canonical implemented reference |
| Pubky SDK PKDNS actor | `/Volumes/vibedrive/vibes-dev/pubky-core/pubky-sdk/src/actors/pkdns.rs` | same as `pubky-core` | Canonical implemented reference |
| Pubky SDK resource addressing | `/Volumes/vibedrive/vibes-dev/pubky-core/pubky-sdk/src/actors/storage/resource.rs` | same as `pubky-core` | Canonical implemented reference |
| Pubky Node PKARR publisher | `/Volumes/vibedrive/vibes-dev/pubky-node` | `5c8ae12e3d0f9fe7bc6eac1278f0e28355f44c82` | Canonical implemented reference for record publishing patterns |
| Upstream pubky-noise | `https://github.com/pubky/pubky-noise` | `40faff7a80ae0197762fea71a3e4d72c636085e0` | Reference only if Pubky-key-compatible encrypted control traffic is required |

## Non-Canonical Context

These documents are useful for vocabulary and threat-model comparison, but they are not standards for Pubkegaard v1.

| Source | Local Path | Treatment |
| --- | --- | --- |
| Local Pubky crypto draft | `/Volumes/vibedrive/vibes-dev/pubky-core/docs/PUBKY_CRYPTO_SPEC.md` | Speculative context only |
| Local unified key delegation draft | `/Volumes/vibedrive/vibes-dev/pubky-core/docs/PUBKY_UNIFIED_KEY_DELEGATION_SPEC_v0.2.md` | Speculative context only |
| Local Paykit and Noise work not present upstream | workspace-local drafts or branches | Non-canonical unless reflected in implemented upstream code |

## Pubkegaard v1 Canonicality Rules

1. Pubky z-base-32 public keys are canonical identity strings.
2. `pubky://<pubky>/<absolute-path>` and `pubky<pubky>/<absolute-path>` addressing follow the implemented SDK resource model.
3. PKARR pointer records follow implemented PKARR signed packet behavior.
4. v1 authentication uses direct Pubky identity signatures unless a canonical implemented delegation API exists.
5. WireGuard is the v1 packet transport. Pubky and PKARR provide identity and discovery, not packet encryption.

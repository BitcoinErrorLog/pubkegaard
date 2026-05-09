# Pubkegaard Relay Specification

Status: beta track profile

## Purpose

Relay mode forwards encrypted WireGuard packets between trusted peers when direct UDP connectivity is unavailable. Relays are transport helpers, not authorities.

## Security Model

A relay must not decrypt inner WireGuard traffic. It may observe relay session metadata such as peer identities, timing, volume, and relay endpoint addresses.

## Authentication

v1 relay clients authenticate by direct Pubky identity signature over a relay request payload. Delegation is a future extension only if a canonical implemented Pubky delegation API exists.

Relay request payload fields:

| Field | Meaning |
| --- | --- |
| `version` | Relay protocol version. |
| `from` | Requesting Pubky identity. |
| `to` | Target Pubky identity. |
| `relay` | Relay Pubky identity or service id. |
| `created_at_ms` | Creation time. |
| `expires_at_ms` | Expiry time. |
| `nonce` | Replay protection value. |

## Limits

A relay must enforce:

1. per-session byte limits
2. per-peer session limits
3. global bandwidth caps where configured
4. expiry-driven session shutdown
5. no logging of inner packet contents

## Beta Acceptance

Relay beta is complete when direct WireGuard remains preferred, fallback works when direct UDP fails, limits are enforced, and relay metadata exposure is documented.

# Pubkegaard Core Specification

Status: initial implementation profile

## Purpose

Pubkegaard is a Pubky-native control plane for trusted-peer WireGuard networks. Pubky identifies peers, PKARR discovers current operational documents, WireGuard carries packets, and local policy decides which routes are allowed.

Pubkegaard is not an anonymity network and does not replace WireGuard cryptography.

## Identity

The canonical Pubkegaard identity is a Pubky z-base-32 public key accepted by the implemented `pkarr::PublicKey` parser.

Display aliases such as `pk:<key>` are non-canonical and must be normalized before policy or signature verification.

## v1 Signing Model

v1 uses direct Pubky identity signatures for Pubkegaard-owned artifacts.

Delegation drafts may inform future versions, but v1 must not depend on speculative local delegation documents. A future delegation profile may be added only when an implemented Pubky API exists.

## Discovery

Each node publishes a compact PKARR TXT record that points to a larger discovery document.

Recommended owner name:

```text
_pubkegaard
```

Recommended TXT value:

```text
v=pkg1;doc=pubky://<pubky>/pub/pubkegaard/v1/discovery.json;h=b3:<hex>;seq=<u64>;exp=<unix_ms>
```

The discovery document is public. It is an offer of connectivity, not authorization.

## Trust Grants

All permissions are local. A remote document cannot grant itself access.

The default effective policy is deny all. A peer may be configured only when a local trust grant permits the specific route or capability.

Core permissions:

| Permission | Meaning |
| --- | --- |
| `mesh` | Peer may communicate with this node over Pubkegaard overlay host routes. |
| `relay_client` | This node may use the peer as a relay. |
| `relay_server` | Peer may use this node as a relay. |
| `exit_client` | This node may route internet traffic through the peer. |
| `exit_server` | Peer may route internet traffic through this node. |
| `lan_client` | This node may route to explicitly advertised LAN routes behind the peer. |
| `lan_server` | Peer may access explicitly configured LAN routes behind this node. |

## Route Authorization

A route is installable only when all conditions hold:

1. The peer identity is valid.
2. The discovery document is current.
3. The WireGuard transport key is bound in the verified discovery document.
4. Local policy permits the route kind.
5. The route does not conflict with protected local routes.

Mesh alpha installs only peer overlay host routes.

## Revocation

Revocation is local and immediate. The controller must remove WireGuard peers, routes, firewall allowances, relay sessions, and exit permissions associated with the revoked identity.

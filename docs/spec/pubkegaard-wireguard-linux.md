# Pubkegaard WireGuard Linux Profile

Status: initial implementation profile

## Interface

The default Linux interface is:

```text
pkg0
```

Implementations may allow a different interface name in local config.

## Mesh Alpha

Mesh alpha installs only peer overlay host routes.

For an IPv4 peer address `100.88.12.34/32` and IPv6 peer address `fd7a:115c:a1e0:1::1234/128`, the generated peer section is:

```ini
[Peer]
PublicKey = <wireguard-public-key>
AllowedIPs = 100.88.12.34/32, fd7a:115c:a1e0:1::1234/128
Endpoint = <host>:<port>
PersistentKeepalive = 25
```

## Route Rules

The controller must authorize every route before installation. Mesh routes are host routes only. Default routes are prohibited until exit mode passes the exit safety gate.

## Firewall

Linux implementation is nftables-first. Firewall changes must be planned before being applied and must roll back to a deny-forwarding safe state on failure.

Mesh alpha does not enable forwarding, NAT, exit, or LAN exposure.

## Exit Gate Requirements

Exit mode must remain disabled until the implementation proves:

1. endpoint route preservation
2. DNS leak protection
3. kill switch behavior
4. rollback to deny-forwarding safe state
5. private and link-local blocklists by default
6. per-peer limits
7. operator warnings and emergency stop

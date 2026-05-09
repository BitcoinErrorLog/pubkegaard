# Pubkegaard Exit Specification

Status: gated release profile

## Purpose

Exit mode lets one trusted peer route internet traffic through another peer. This creates operator risk and must remain disabled until all safety gates pass.

## Exit Client

Before using a peer as exit, the controller must verify:

1. the peer identity is valid
2. the peer discovery document is current
3. the peer advertises exit capability
4. local policy grants `exit_client`
5. the peer grants this identity `exit_server`
6. endpoint route preservation is configured
7. DNS mode is configured
8. kill switch behavior is available

## Exit Server

Before serving exit traffic, the controller must verify:

1. local policy grants `exit_server` to the peer
2. the peer has a stable overlay source address
3. NAT applies only to that overlay source
4. forwarding to private and link-local ranges is blocked unless separate LAN permission exists
5. per-peer limits are configured or explicitly disabled by the operator

## Safety Defaults

Exit server mode blocks private, loopback, link-local, multicast, and reserved ranges by default. SMTP port 25 should be blocked by default.

## Release Gate

Exit mode may ship only after tests prove that route changes do not capture the peer endpoint, DNS does not leak by default, firewall failure closes safely, and revocation immediately removes NAT and forwarding permissions.

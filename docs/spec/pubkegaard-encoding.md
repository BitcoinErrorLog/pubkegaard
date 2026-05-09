# Pubkegaard Encoding and Signing Profile

Status: initial implementation decision

## Decision

Pubkegaard v1 owns its signed object encoding. It does not inherit encoding rules from speculative local crypto or delegation drafts.

For launch, Pubkegaard uses JSON objects with fixed schemas for public discovery, policy export, relay requests, and status APIs. Implementations must reject unknown object `type` values, unsupported versions, expired objects, stale sequence numbers, and malformed routes before applying configuration.

## Signature Domains

Every signed object type must use a distinct domain string:

| Object | Domain |
| --- | --- |
| Discovery document | `pubkegaard.discovery.v1` |
| Relay request | `pubkegaard.relay.request.v1` |
| Relay accept | `pubkegaard.relay.accept.v1` |
| Revocation list | `pubkegaard.revocation.v1` |

The v1 libraries model and validate these payloads. Signature attachment and verification are intentionally isolated so a future canonical Pubky delegated signing API can be added without changing route policy semantics.

## Identity Format

Canonical identity strings are z-base-32 Pubky public keys accepted by implemented `pkarr::PublicKey` parsing.

## Future Encoding Changes

If Pubky later exposes canonical typed signing, deterministic CBOR, or delegation APIs, Pubkegaard may add a new signed-object profile under a new version. v1 direct identity signatures remain valid for v1 objects.

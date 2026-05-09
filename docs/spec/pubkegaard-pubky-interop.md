# Pubkegaard Pubky Interop Profile

Status: initial implementation profile

## Canonical Inputs

Pubkegaard uses implemented Pubky SDK and PKARR behavior as its compatibility baseline.

Canonical identity strings are z-base-32 public keys accepted by `pkarr::PublicKey`.

Canonical public storage addresses follow the implemented SDK model:

```text
pubky://<pubky>/pub/pubkegaard/v1/discovery.json
pubky<pubky>/pub/pubkegaard/v1/discovery.json
```

Session-scoped writes use absolute paths:

```text
/pub/pubkegaard/v1/discovery.json
```

## PKARR Records

Pubkegaard compact pointer records use normal PKARR signed packets. The initial profile uses TXT records because implemented record publishing already supports TXT.

The compact pointer is not an authorization object. It only helps a resolver locate and verify a larger discovery document.

## Public Documents

Recommended public paths:

```text
/pub/pubkegaard/v1/discovery.json
/pub/pubkegaard/v1/revocations.json
/pub/pubkegaard/v1/relays/<relay_id>.json
```

The path prefix is versioned to allow future incompatible protocol revisions.

## Signing

v1 signs Pubkegaard-owned documents directly with the Pubky identity key. The signed payload must include:

1. document type
2. version
3. identity
4. sequence
5. expiry

The signature input must use a Pubkegaard-specific domain string. Draft key delegation specs are not normative for v1.

## Speculative Draft Handling

Local `PUBKY_CRYPTO_SPEC` and unified key delegation drafts are not standards for Pubkegaard. They may be cited only as non-canonical context. If the implemented Pubky SDK later exposes canonical delegation or typed signing APIs, Pubkegaard may add an extension profile without changing v1 direct identity signatures.

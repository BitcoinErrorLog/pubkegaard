# Release Gates

## Mesh Alpha Gate

Mesh alpha may be tagged when:

1. source baseline is recorded
2. discovery pointer parsing and document validation tests pass
3. policy denies default routes under mesh-only grants
4. WireGuard mesh peer sections render host routes only
5. revocation produces a rollback/removal firewall plan

## Relay Beta Gate

Relay beta may be tagged when:

1. relay requests validate identity, expiry, nonce, and byte limits
2. direct WireGuard remains preferred
3. relay fallback is integration tested
4. relay metadata exposure is documented
5. relay does not log inner packets

## Exit Release Gate

Exit mode may be enabled only when:

1. endpoint route preservation is tested
2. DNS leak protection is tested
3. kill switch failure closes safely
4. firewall rollback returns to deny-forwarding state
5. private and link-local ranges are blocked by default
6. revocation removes NAT and forwarding permissions immediately

The current implementation keeps exit disabled and exposes the gate requirements through `pubkegaardd exit-gate`.

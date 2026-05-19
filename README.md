# KXCO Chain — Independent Attestation Verifier

**This directory is intentionally public.** It contains everything an independent third party needs to verify, end-to-end, that KXCO Chain's validators are signing each finalised block with a post-quantum (ML-DSA-65) key that matches the public key registered on-chain.

You do not need to trust KXCO. You verify against:
1. The signed attestation feed (published to a GitHub Gist, NDJSON).
2. The on-chain `PQCRegistry` contract (canonical source of each validator's public key).
3. The KXCO Chain RPC endpoint (used to confirm the block hash being attested actually corresponds to a block on the chain).

If any of those three sources disagree, this verifier flags it.

## What you need

- Node.js 22+
- The public Gist URLs (one per validator) — published below
- The `PQCRegistry` contract address — published below
- The KXCO Chain RPC URL: `https://chain.kxco.ai/rpc`

## Public references

The attestation sidecars are running on the production network and the registry is live. Gist publication remains pending (operator needs to provision a GitHub token); until then the NDJSON feed is read directly off the validator hosts. See "Reading the feed without a Gist" below.

| Resource | Location |
|---|---|
| `PQCRegistry` contract | `0xa0c2133b71b613Cbf9f0649D9489223DaaC3EE52` |
| Chain RPC | `https://chain.kxco.ai/rpc` |
| Validator 1 address | `0xc0f4710F6d73EE812D64A9f0d2A909AE702Df91e` — registered ✅ |
| Validator 2 address | `0x7f74a28c7333Ab82e56CbAB5794BF982da42B093` — registered ✅ |
| Validator 3 address | `0x58b9293658001a39437839AB418eD8D6A8e79FbF` — registered ✅ |
| Validator 4 address | `0xc2b059EA5A0E489BD4b92b488625Cab87c5e46d4` — pending (key format being migrated to FIPS 204 ML-DSA-65) |
| Validator 1 Gist | _(pending — operator provisioning GitHub token)_ |
| Validator 2 Gist | _(pending)_ |
| Validator 3 Gist | _(pending)_ |
| Validator 4 Gist | _(pending — see validator 4 note above)_ |

### Reading the feed without a Gist

Until the Gist publication is provisioned, the NDJSON feed is accessible to anyone with operator-level access to the validator hosts. The sidecars are writing to `/attestations/nodeN-attestations.ndjson` inside the `kxco-attestation-nodeN` container. An operator can `docker exec` and copy the file out, or sync the `attestation-data` volume to a publicly-readable storage location. Once a Gist is provisioned, the URLs above will be filled in.

## How to run

```bash
# 1. Install dependencies (audited, no native code)
npm ci

# 2. Verify a single validator's attestation feed
node verify.js https://gist.githubusercontent.com/<user>/<gist-id>/raw/kxco-attestations-node1.ndjson

# 3. Verify all four feeds against the on-chain registry
node verify-all.js
```

A successful run prints:

```
Validator 1: 12,847 attestations verified  PASS
Validator 2: 12,847 attestations verified  PASS
Validator 3: 12,847 attestations verified  PASS
Validator 4: 12,847 attestations verified  PASS

All 51,388 attestations verified end-to-end against:
  - The signed NDJSON feeds (Gist)
  - The on-chain PQCRegistry public keys
  - The block hashes reported by https://chain.kxco.ai/rpc
```

A failure prints the offending block number, expected/actual values, and exits non-zero.

## What the verifier checks per attestation

For each line in each NDJSON feed:

1. **Block hash match.** The verifier calls `eth_getBlockByNumber` on the KXCO Chain RPC for the block number in the attestation. The hash returned must equal `entry.blockHash`.
2. **Message canonicalisation.** Recomputes `keccak256(chainId ‖ blockNumber ‖ blockHash)` and confirms it equals `entry.messageHex`.
3. **Signature verification.** Calls `mlDsa65.verify(publicKey, message, signature)`. The `publicKey` is read from the on-chain `PQCRegistry` (not from the Gist), so a malicious Gist publisher cannot substitute a key.
4. **Sequential coverage.** Optionally, with `--strict`, the verifier checks for gaps — every block from the first attested through the last must have an entry.

## Why this is the trust anchor

The chain's claim of post-quantum block authenticity rests on:
- The ML-DSA-65 algorithm (FIPS 204, no known classical or quantum break).
- The fact that the public key on-chain is the same key whose signatures appear in the feed.
- The fact that the feed signatures verify against that key.

This verifier confirms all three. If you run it against the live feeds and it returns 0, you have direct evidence — not trust — that every attested block was signed by the key the chain claims it should be signed by.

## Reporting an issue

If this verifier flags a failure on the production feeds, file a public issue immediately. A discrepancy between the chain, the registry, and the feed is a P0 security event.

## Licence

MIT. Take this code, port it, audit it, fork it.

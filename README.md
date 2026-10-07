# KXCO Chain: Independent Attestation Verifier

**This directory is intentionally public.** It contains what an independent third party needs to check, end to end, that each KXCO Chain validator signs every finalised block with its post-quantum ML-DSA (FIPS 204) attestation key.

You check three things against three sources:

1. The attestation feed (NDJSON, one record per block per validator).
2. The published key history (`validator-keys.json`): each validator's public keys, the blocks each key signed, and a signed rotation manifest for every key change.
3. The KXCO Chain RPC endpoint, which confirms that each attested block hash is the chain's block at that height.

If any of those disagree, this verifier flags it.

## What you need

- Node.js 22+
- A feed: the rolling window in `attestations/kxco-attestations-node<N>-latest.ndjson`, or a full day from the repository's releases (`node<N>-<date>.ndjson.gz`)
- The key history: `attestations/validator-keys.json`
- The KXCO Chain RPC URL: `https://chain.kxco.ai/rpc`

## How to run

```bash
# 1. Install dependencies (two audited libraries, no native code)
npm ci

# 2. Verify a validator's rolling window
node verify.js https://raw.githubusercontent.com/KnightsbridgeAIQ/kxco-attestations/main/attestations/kxco-attestations-node1-latest.ndjson \
  --keys https://raw.githubusercontent.com/KnightsbridgeAIQ/kxco-attestations/main/attestations/validator-keys.json

# 3. Verify a full day, gzipped as released, and check for gaps
node verify.js node1-2026-10-05.ndjson.gz --keys validator-keys.json --strict

# 4. All four validators' current windows, straight from this repository and the chain
node verify_live.js --strict
```

A successful run ends:

```text
ML-DSA-65 0x563e34dd4fb564bdc61b9487303292290d92eaf2: 100 verified
Verified: 100  Failed: 0  Total: 100

All attestations verified end-to-end.
```

A failure prints the block number and the reason, and exits 1. Exit 2 means a feed, key file or RPC could not be read.

Options:

- `--keys <file-or-url>`: the key history (repeatable). A validator manifest (`kxco-manifest-node<N>.json`) is also accepted.
- `--registry <address>`: read each key from a contract exposing `getPublicKey(address)`, looked up by the record's `pqcAddress`, instead of `--keys`.
- `--rpc <url>`: the chain RPC used for the block-hash check.
- `--strict`: also fail on any gap in block numbers for a validator.

## What the verifier checks per attestation

1. **Message canonicalisation.** Recomputes `keccak256(chainId ‖ blockNumber ‖ blockHash)` and confirms it equals `messageHex`.
2. **The right key.** Each record names the `pqcAddress` of the key that signed it. The verifier takes that key from the key history, never from the feed, and refuses a record whose key is not listed, belongs to another validator, or is outside the blocks published for that key.
3. **Block hash match.** Calls `eth_getBlockByNumber` on the chain RPC; the hash returned must equal `blockHash`.
4. **Signature verification.** Verifies the signature with the parameter set of the key: a 1,952-byte key is ML-DSA-65 and a 2,592-byte key is ML-DSA-87 (public key sizes per FIPS 204, Table 2). A record whose `algorithm` label names the other set fails.
5. **Sequential coverage.** With `--strict`, every block from the first attested through the last must have a record.

## The key history

Every key in `validator-keys.json` is checked before any record is read:

- `pqcAddress` must be the last 20 bytes of `keccak256(publicKey)`, so an address names exactly one key.
- `kid` must be the first 16 hex characters of `SHA-256(publicKey)`.
- `firstBlock` and `lastBlock` bound the blocks a key signed (`null` leaves an end open). A key cannot sign for a block after its retirement.
- Each entry in `rotations` is a rotation manifest (version 1.0, RFC 8785 canonical JSON) signed by the outgoing key and naming the incoming key. Anyone who trusts a validator's earlier key can confirm that the same holder introduced the next one.

A history that fails any of these is refused as a whole.

## Reporting an issue

If this verifier flags a failure on the production feeds, file a public issue immediately. A discrepancy between the chain, the key history and the feed is a P0 security event.

## Licence

MIT. Take this code, port it, audit it, fork it.

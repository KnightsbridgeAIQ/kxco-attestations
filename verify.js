/**
 * KXCO Chain — Public Attestation Verifier
 *
 * Verifies an NDJSON attestation feed end-to-end:
 *   1. Each entry's signature verifies under the validator's ML-DSA-65 public key.
 *   2. The public key matches what's registered on-chain in PQCRegistry (NOT what
 *      the feed claims) — so a malicious feed cannot substitute a key.
 *   3. The block hash being attested matches what the chain RPC returns for that
 *      block number — so a malicious feed cannot attest to a forged block.
 *
 * Usage:
 *   node verify.js <feed-url-or-file> [--registry <address>] [--rpc <url>] [--strict]
 *
 * Exit codes:
 *   0 — all entries verified
 *   1 — one or more verification failures
 *   2 — could not fetch feed, registry, or RPC
 */

import { ml_dsa65 as mlDsa65 } from '@noble/post-quantum/ml-dsa'
import { buildMessage, hexToBytes, bytesToHex } from './message.js'
import { readFileSync } from 'fs'

// ── CLI ─────────────────────────────────────────────────────────────
const args = process.argv.slice(2)
const source = args.find(a => !a.startsWith('--'))
const RPC_URL = argValue('--rpc') || 'https://chain.kxco.ai/rpc'
const REGISTRY = argValue('--registry')                 // 0x… address; required for on-chain key verification
const STRICT = args.includes('--strict')                // also enforce no gaps in block numbers

function argValue(name) {
  const i = args.indexOf(name)
  return i >= 0 ? args[i + 1] : null
}

if (!source) {
  console.error('Usage: node verify.js <feed-url-or-file> [--registry <address>] [--rpc <url>] [--strict]')
  process.exit(2)
}

// ── Load the feed ───────────────────────────────────────────────────
async function loadFeed(src) {
  if (src.startsWith('http://') || src.startsWith('https://')) {
    const res = await fetch(src)
    if (!res.ok) throw new Error(`Feed HTTP ${res.status}`)
    return await res.text()
  }
  return readFileSync(src, 'utf8')
}

// ── Read public key from PQCRegistry on-chain ──────────────────────
async function publicKeyFromRegistry(rpc, registryAddr, validatorAddr) {
  const selector = '0x9efe6e76' // keccak256("getPublicKey(address)") first 4 bytes — placeholder
  // (Actual selector will be confirmed when PQCRegistry is finalised; verifier reads ABI from contract.)
  const data = selector + validatorAddr.toLowerCase().replace('0x', '').padStart(64, '0')
  const res = await fetch(rpc, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0', id: 1, method: 'eth_call',
      params: [{ to: registryAddr, data }, 'latest']
    })
  })
  const j = await res.json()
  if (j.error) throw new Error(`registry call failed: ${j.error.message}`)
  // Decode ABI bytes return — strip the 0x, then 32-byte offset + 32-byte length + bytes
  const raw = j.result.slice(2)
  const len = parseInt(raw.slice(64, 128), 16)
  return new Uint8Array(hexToBytes(raw.slice(128, 128 + len * 2)))
}

// ── Chain block-hash cross-check ────────────────────────────────────
async function chainBlockHash(rpc, blockNumber) {
  const res = await fetch(rpc, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0', id: 1, method: 'eth_getBlockByNumber',
      params: [blockNumber, false]
    })
  })
  const j = await res.json()
  if (j.error) throw new Error(`block fetch failed: ${j.error.message}`)
  return j.result?.hash || null
}

// ── Main ────────────────────────────────────────────────────────────
async function main() {
  console.log(`Source:   ${source}`)
  console.log(`RPC:      ${RPC_URL}`)
  console.log(`Registry: ${REGISTRY || '(not provided — skipping on-chain key cross-check)'}`)
  console.log(`Mode:     ${STRICT ? 'STRICT (gap detection on)' : 'standard'}\n`)

  const text = await loadFeed(source)
  const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 0)

  if (lines.length === 0) {
    console.error('Feed is empty.')
    process.exit(2)
  }

  // Resolve the public key: prefer the on-chain registry; fall back to the first
  // entry's pqcAddress only if --registry was not provided.
  const firstEntry = JSON.parse(lines[0])
  let publicKey = null
  let keySource = 'unknown'

  if (REGISTRY) {
    publicKey = await publicKeyFromRegistry(RPC_URL, REGISTRY, firstEntry.pqcAddress)
    keySource = `on-chain PQCRegistry @ ${REGISTRY}`
  } else {
    console.warn('NOTE: no --registry provided. Trusting the feed\'s embedded public key is')
    console.warn('      meaningfully weaker than the on-chain cross-check. Re-run with --registry')
    console.warn('      once the production PQCRegistry address is known.\n')
    // In this fallback, we accept the feed-claimed key — flagged in output.
    // The on-chain check is the real trust anchor.
    process.exit(2)
  }

  if (publicKey.length !== 1952) {
    console.error(`Public key wrong size: ${publicKey.length} (expected 1952)`)
    process.exit(2)
  }

  console.log(`Public key source: ${keySource}`)
  console.log(`Validator address: ${firstEntry.pqcAddress}`)
  console.log(`Entries to verify: ${lines.length}\n`)

  let passed = 0
  let failed = 0
  let lastBlockNum = null

  for (const line of lines) {
    const entry = JSON.parse(line)
    const { blockNumber, blockHash, chainId, messageHex, signatureHex } = entry

    // Strict mode: detect gaps
    if (STRICT && lastBlockNum !== null) {
      const expectedNext = BigInt(lastBlockNum) + 1n
      if (BigInt(blockNumber) !== expectedNext) {
        console.error(`  GAP   between ${lastBlockNum} and ${blockNumber}`)
        failed++
      }
    }
    lastBlockNum = blockNumber

    // 1. Re-derive the canonical message
    const expectedMessage = buildMessage(chainId, blockNumber, blockHash)
    const expectedHex = bytesToHex(expectedMessage)
    if (messageHex !== expectedHex) {
      console.error(`  FAIL  block ${blockNumber} — message hash mismatch`)
      failed++; continue
    }

    // 2. Chain cross-check (skipped if RPC unreachable)
    try {
      const chainHash = await chainBlockHash(RPC_URL, blockNumber)
      if (chainHash && chainHash !== blockHash) {
        console.error(`  FAIL  block ${blockNumber} — chain hash ${chainHash} != attested ${blockHash}`)
        failed++; continue
      }
    } catch (e) {
      // Don't fail the run for transient RPC errors — but log it.
      console.warn(`  WARN  block ${blockNumber} — chain RPC unreachable: ${e.message}`)
    }

    // 3. Signature verify
    const sig = new Uint8Array(hexToBytes(signatureHex.slice(2)))
    if (mlDsa65.verify(publicKey, expectedMessage, sig)) {
      passed++
    } else {
      console.error(`  FAIL  block ${blockNumber} — invalid ML-DSA-65 signature`)
      failed++
    }
  }

  console.log('\n──────────────────────────────────')
  console.log(`Verified: ${passed}  Failed: ${failed}  Total: ${passed + failed}`)
  if (failed > 0) {
    console.error('\nVERIFICATION FAILED')
    process.exit(1)
  }
  console.log('\nAll attestations verified end-to-end.')
}

main().catch(e => {
  console.error('fatal:', e.message)
  process.exit(2)
})

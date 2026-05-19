// End-to-end verification using @noble/post-quantum + the live KXCO Chain.
//   1. Fetch the public key from on-chain PQCRegistry
//   2. Verify every ML-DSA-65 signature in the feed under that key
//   3. Cross-check a sample of block hashes against the chain RPC
//
// Usage: node verify_live.js <validator-address> <feed-file>

import { ml_dsa65 as mlDsa65 } from '@noble/post-quantum/ml-dsa'
import { keccak_256 } from '@noble/hashes/sha3'
import { readFileSync } from 'fs'

const RPC = "https://chain.kxco.ai/rpc"
const REGISTRY = "0xa0c2133b71b613Cbf9f0649D9489223DaaC3EE52"
const VALIDATOR = process.argv[2] || "0xc0f4710F6d73EE812D64A9f0d2A909AE702Df91e"
const FEED = process.argv[3] || "F:/Development/kxco-tmp/node1-feed.ndjson"

function hexToBytes(h) {
  const b = new Uint8Array(h.length / 2)
  for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i*2, i*2+2), 16)
  return b
}

function buildMessage(chainId, blockNumber, blockHash) {
  const buf = new Uint8Array(44)
  const v = new DataView(buf.buffer)
  v.setUint32(0, chainId, false)
  v.setBigUint64(4, BigInt(blockNumber), false)
  buf.set(hexToBytes(blockHash.slice(2)), 12)
  return keccak_256(buf)
}

async function rpc(method, params) {
  const r = await fetch(RPC, {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({jsonrpc: '2.0', id: 1, method, params})
  })
  const j = await r.json()
  if (j.error) throw new Error(j.error.message)
  return j.result
}

const selector = '0x' + Buffer.from(keccak_256(new TextEncoder().encode("getPublicKey(address)"))).slice(0,4).toString('hex')
const raw = await rpc('eth_call', [{to: REGISTRY, data: selector + VALIDATOR.slice(2).toLowerCase().padStart(64, '0')}, 'latest'])
const rawNo0x = raw.slice(2)
const len = parseInt(rawNo0x.slice(64, 128), 16)
const pubkey = hexToBytes(rawNo0x.slice(128, 128 + len*2))
console.log(`Validator: ${VALIDATOR}`)
console.log(`On-chain pubkey: ${pubkey.length} bytes (expected 1952)`)

if (pubkey.length !== 1952) { console.error("WRONG SIZE"); process.exit(1) }

const lines = readFileSync(FEED, 'utf8').split('\n').filter(l => l.trim())
console.log(`Feed entries: ${lines.length}\n`)

let passed = 0, failed = 0
for (const line of lines) {
  const e = JSON.parse(line)
  const msg = buildMessage(e.chainId, e.blockNumber, e.blockHash)
  const sig = hexToBytes(e.signatureHex.slice(2))
  if (mlDsa65.verify(pubkey, msg, sig)) passed++
  else { failed++; console.log(`  FAIL block ${e.blockNumber}`) }
}
console.log(`Signatures: ${passed} verified, ${failed} failed`)

const sampleSize = Math.min(10, lines.length)
const step = Math.max(1, Math.floor(lines.length / sampleSize))
let rpcOk = 0, rpcMiss = 0
for (let i = 0; i < lines.length; i += step) {
  const e = JSON.parse(lines[i])
  const block = await rpc('eth_getBlockByNumber', [e.blockNumber, false])
  if (block && block.hash === e.blockHash) { rpcOk++ }
  else { rpcMiss++; console.log(`  block ${e.blockNumber}: MISMATCH`) }
}
console.log(`Block-hash cross-check: ${rpcOk} match, ${rpcMiss} mismatch`)

if (failed === 0 && rpcMiss === 0) {
  console.log(`\n══════════════════════════════════════════════`)
  console.log(`  END-TO-END VERIFICATION SUCCESS  (${VALIDATOR})`)
  console.log(`══════════════════════════════════════════════`)
}

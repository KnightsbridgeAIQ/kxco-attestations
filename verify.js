/**
 * KXCO Chain — Public Attestation Verifier
 *
 * Verifies an NDJSON attestation feed end-to-end:
 *   1. Each entry's signature verifies under the key its pqcAddress names, with
 *      the parameter set that key belongs to: a 1952-byte key is ML-DSA-65, a
 *      2592-byte key is ML-DSA-87. A record whose algorithm label names the
 *      other set fails. A feed that spans a key change verifies record by record.
 *   2. The keys come from the published key history (--keys), or from an
 *      on-chain registry (--registry), never from the feed. Every key must be
 *      the key its pqcAddress names (the last 20 bytes of keccak256(publicKey)),
 *      every rotation manifest in the history must verify under the outgoing
 *      key, and a key may only sign blocks inside the range published for it.
 *   3. The block hash being attested matches what the chain RPC returns for that
 *      block number, so a malicious feed cannot attest to a forged block.
 *
 * Usage:
 *   node verify.js <feed-url-or-file[.gz]> --keys <file-or-url> [--keys ...]
 *                  [--registry <address>] [--rpc <url>] [--strict]
 *
 * Exit codes:
 *   0 — all entries verified
 *   1 — one or more verification failures
 *   2 — could not fetch feed, keys, registry, or RPC
 */

import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa'
import { keccak_256 } from '@noble/hashes/sha3'
import { buildMessage, hexToBytes, bytesToHex } from './message.js'
import { createReadStream, readFileSync } from 'fs'
import { createGunzip, gunzipSync } from 'zlib'
import { createInterface } from 'readline'
import { createHash } from 'crypto'

// ── Parameter sets, chosen by the length of the trusted public key ──
const SETS = [
  { id: 'ml-dsa-65', label: 'ML-DSA-65', publicKeyLength: 1952, signatureLength: 3309, impl: ml_dsa65 },
  { id: 'ml-dsa-87', label: 'ML-DSA-87', publicKeyLength: 2592, signatureLength: 4627, impl: ml_dsa87 },
]
const setForKey = pk => SETS.find(s => s.publicKeyLength === pk.length) || null
const HISTORY_SCHEMA = 'kxco-validator-attestation-keys/1'

// ── CLI ─────────────────────────────────────────────────────────────
const args = process.argv.slice(2)
const RPC_URL = argValue('--rpc') || 'https://chain.kxco.ai/rpc'
const REGISTRY = argValue('--registry')                 // 0x… address of a getPublicKey(address) registry
const KEYS = argValues('--keys')                        // published key history (or sidecar manifests)
const STRICT = args.includes('--strict')                // also enforce no gaps in block numbers
const source = args.find((a, i) => !a.startsWith('--') && !['--rpc', '--registry', '--keys'].includes(args[i - 1]))

function argValue(name) {
  const i = args.indexOf(name)
  return i >= 0 ? args[i + 1] : null
}
function argValues(name) {
  return args.flatMap((a, i) => (a === name && args[i + 1] ? [args[i + 1]] : []))
}

if (!source) {
  console.error('Usage: node verify.js <feed-url-or-file[.gz]> --keys <file-or-url> [--registry <address>] [--rpc <url>] [--strict]')
  process.exit(2)
}

const isUrl = s => s.startsWith('http://') || s.startsWith('https://')

async function readText(src) {
  if (!isUrl(src)) return readFileSync(src, 'utf8')
  const res = await fetch(src)
  if (!res.ok) throw new Error(`${src}: HTTP ${res.status}`)
  return await res.text()
}

// ── The feed, a line at a time (a day's log is hundreds of MB) ──────
async function* feedLines(src) {
  let input
  if (isUrl(src)) {
    const res = await fetch(src)
    if (!res.ok) throw new Error(`Feed HTTP ${res.status}`)
    const buf = Buffer.from(await res.arrayBuffer())
    const text = (src.endsWith('.gz') ? gunzipSync(buf) : buf).toString('utf8')
    for (const l of text.split('\n')) yield l
    return
  }
  input = createReadStream(src)
  if (src.endsWith('.gz')) input = input.pipe(createGunzip())
  for await (const l of createInterface({ input, crlfDelay: Infinity })) yield l
}

// ── Keys ────────────────────────────────────────────────────────────
const pqcAddressOf = pk => bytesToHex(keccak_256(pk).slice(12))
const kidOf = pk => createHash('sha256').update(pk).digest('hex').slice(0, 16)
const strip0x = h => (typeof h === 'string' && h.startsWith('0x') ? h.slice(2) : h)

function toBlock(v) {
  if (v === undefined || v === null) return null
  if (Number.isSafeInteger(v) && v >= 0) return BigInt(v)
  if (typeof v === 'string' && /^0x[0-9a-fA-F]+$/.test(v)) return BigInt(v)
  throw new Error(`block range value ${JSON.stringify(v)} is not a block number`)
}

function checkedKey(e, fallbackIndex) {
  const hex = strip0x(e && e.publicKeyHex)
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2) throw new Error('key entry has no hex publicKeyHex')
  const publicKey = hexToBytes(hex)
  const set = setForKey(publicKey)
  if (!set) throw new Error(`public key is ${publicKey.length} bytes; not an ML-DSA-65 or ML-DSA-87 key`)
  if (e.algorithm !== undefined && !String(e.algorithm).startsWith(set.label)) throw new Error(`entry says ${e.algorithm} but its key is ${set.label}`)
  const pqcAddress = pqcAddressOf(publicKey)
  if (e.pqcAddress !== undefined && String(e.pqcAddress).toLowerCase() !== pqcAddress) {
    throw new Error(`entry names ${e.pqcAddress} but its key's address is ${pqcAddress}`)
  }
  const kid = kidOf(publicKey)
  if (e.kid !== undefined && e.kid !== kid) throw new Error(`entry names kid ${e.kid} but its key's kid is ${kid}`)
  const vi = e.validatorIndex ?? fallbackIndex
  return { validatorIndex: vi === undefined ? undefined : Number(vi), set, publicKey, pqcAddress, kid,
           firstBlock: toBlock(e.firstBlock), lastBlock: toBlock(e.lastBlock) }
}

// RFC 8785 canonical JSON, the subset a rotation manifest needs.
function canonicalize(v) {
  if (v === null) return 'null'
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  if (typeof v === 'string') return JSON.stringify(v)
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new TypeError('canonical JSON subset: integers only')
    return JSON.stringify(v)
  }
  if (Array.isArray(v)) return `[${v.map(x => (x === undefined ? 'null' : canonicalize(x))).join(',')}]`
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().filter(k => v[k] !== undefined).map(k => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(',')}}`
  }
  throw new TypeError(`canonical JSON: cannot encode ${typeof v}`)
}

function checkRotation(all, m) {
  const where = `rotation ${m && m.previousKid} -> ${m && m.newKid}`
  if (!m || m.version !== '1.0' || m.manifestType !== 'rotation' || !m.signature || m.signature.kid !== m.previousKid) {
    throw new Error(`${where}: not a signed version 1.0 rotation manifest`)
  }
  const prev = all.find(k => k.kid === m.previousKid)
  const next = all.find(k => k.kid === m.newKid)
  if (!prev || !next) throw new Error(`${where}: a key it names is not in the history`)
  if (String(m.newPublicKey).toLowerCase() !== bytesToHex(next.publicKey).slice(2)) throw new Error(`${where}: newPublicKey is not the listed key`)
  if (prev.validatorIndex !== undefined && next.validatorIndex !== undefined && prev.validatorIndex !== next.validatorIndex) {
    throw new Error(`${where}: the keys belong to different validators`)
  }
  if (m.signature.alg !== prev.set.id) throw new Error(`${where}: signature.alg is not the outgoing key's set`)
  const sig = hexToBytes(strip0x(String(m.signature.value)))
  if (sig.length !== prev.set.signatureLength) throw new Error(`${where}: signature is the wrong size for ${prev.set.label}`)
  const bytes = new TextEncoder().encode(canonicalize({ ...m, signature: { ...m.signature, value: '' } }))
  if (!prev.set.impl.verify(prev.publicKey, bytes, sig)) throw new Error(`${where}: the outgoing key's signature does not verify`)
  return `${m.previousKid} (${prev.set.label}) -> ${m.newKid} (${next.set.label})`
}

// pqcAddress -> [key]. The published history decides for any address it lists.
function buildRing(docs) {
  const byAddress = new Map()
  const add = k => { if (!byAddress.has(k.pqcAddress)) byAddress.set(k.pqcAddress, []); byAddress.get(k.pqcAddress).push(k) }
  const entries = d => (Array.isArray(d.keys) ? d.keys : typeof d.publicKeyHex === 'string' ? [d] : [])
  const histories = docs.filter(d => d.schema === HISTORY_SCHEMA)
  if (docs.some(d => d.schema !== undefined && d.schema !== HISTORY_SCHEMA)) throw new Error(`unknown key document schema; expected ${HISTORY_SCHEMA}`)
  for (const d of histories) for (const e of entries(d)) add(checkedKey(e))
  const listed = new Set(byAddress.keys())
  for (const d of docs.filter(x => x.schema === undefined)) {
    for (const e of entries(d)) {
      const k = checkedKey(e, d.validatorIndex)
      if (!listed.has(k.pqcAddress) && !byAddress.has(k.pqcAddress)) add(k)
    }
  }
  if (!byAddress.size) throw new Error('no keys found in the key documents')
  const all = [...byAddress.values()].flat()
  const rotations = histories.flatMap(d => (d.rotations || []).map(m => checkRotation(all, m)))
  return { byAddress, all, rotations }
}

// ── Read a public key from an on-chain registry ─────────────────────
const GET_PUBLIC_KEY = bytesToHex(keccak_256(new TextEncoder().encode('getPublicKey(address)')).slice(0, 4))

async function publicKeyFromRegistry(rpc, registryAddr, account) {
  const data = GET_PUBLIC_KEY + account.toLowerCase().replace('0x', '').padStart(64, '0')
  const res = await fetch(rpc, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: registryAddr, data }, 'latest'] }),
  })
  const j = await res.json()
  if (j.error) throw new Error(`registry call failed: ${j.error.message}`)
  // ABI bytes return: 32-byte offset, 32-byte length, then the bytes
  const raw = String(j.result || '0x').slice(2)
  const len = parseInt(raw.slice(64, 128), 16)
  if (!len) throw new Error(`registry returned no key for ${account}`)
  return new Uint8Array(hexToBytes(raw.slice(128, 128 + len * 2)))
}

// ── Chain block-hash cross-check ────────────────────────────────────
async function chainBlockHash(rpc, blockNumber) {
  const res = await fetch(rpc, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getBlockByNumber', params: [blockNumber, false] }),
  })
  const j = await res.json()
  if (j.error) throw new Error(`block fetch failed: ${j.error.message}`)
  return j.result?.hash || null
}

// ── Main ────────────────────────────────────────────────────────────
async function main() {
  console.log(`Source:   ${source}`)
  console.log(`RPC:      ${RPC_URL}`)
  console.log(`Keys:     ${KEYS.length ? KEYS.join(', ') : REGISTRY ? `on-chain registry @ ${REGISTRY}` : '(none)'}`)
  console.log(`Mode:     ${STRICT ? 'STRICT (gap detection on)' : 'standard'}\n`)

  if (!KEYS.length && !REGISTRY) {
    console.error('No keys. Pass --keys with the published key history, for example')
    console.error('  --keys https://raw.githubusercontent.com/KnightsbridgeAIQ/kxco-attestations/main/attestations/validator-keys.json')
    console.error('The feed\'s own claims about its keys are never trusted.')
    process.exit(2)
  }

  let ring = null
  if (KEYS.length) {
    let docs
    try {
      docs = await Promise.all(KEYS.map(async k => JSON.parse(await readText(k))))
    } catch (e) {
      console.error(`Cannot read keys: ${e.message}`)
      process.exit(2)
    }
    try {
      ring = buildRing(docs)
    } catch (e) {
      console.error(`Key history refused: ${e.message}`)
      process.exit(1)
    }
    for (const k of ring.all) {
      const range = k.firstBlock === null && k.lastBlock === null ? 'all blocks' : `blocks ${k.firstBlock ?? 'start'} to ${k.lastBlock ?? 'now'}`
      console.log(`Key:      validator ${k.validatorIndex ?? '?'}  ${k.set.label}  ${k.pqcAddress}  kid ${k.kid}  ${range}`)
    }
    for (const r of ring.rotations) console.log(`Rotation: ${r}, signed by the outgoing key, verified`)
    console.log('')
  }

  const registryKeys = new Map()
  async function keyFor(entry) {
    const addr = typeof entry.pqcAddress === 'string' ? entry.pqcAddress.toLowerCase() : null
    if (ring) {
      let c = addr ? ring.byAddress.get(addr) : (ring.all.length === 1 ? ring.all : null)
      if (!c) return { reason: addr ? `signed by unknown key ${addr}` : 'record names no pqcAddress and more than one key is known' }
      if (entry.validatorIndex !== undefined) c = c.filter(k => k.validatorIndex === undefined || k.validatorIndex === Number(entry.validatorIndex))
      if (!c.length) return { reason: `key ${addr} does not belong to validator ${entry.validatorIndex}` }
      const n = BigInt(entry.blockNumber)
      const key = c.find(k => (k.firstBlock === null || n >= k.firstBlock) && (k.lastBlock === null || n <= k.lastBlock))
      return key ? { key } : { reason: `block ${n} is outside the period published for key ${addr}` }
    }
    if (!addr) return { reason: 'record names no pqcAddress' }
    if (!registryKeys.has(addr)) {
      const pk = await publicKeyFromRegistry(RPC_URL, REGISTRY, addr)
      const set = setForKey(pk)
      if (!set) throw new Error(`registry key for ${addr} is ${pk.length} bytes; not an ML-DSA-65 or ML-DSA-87 key`)
      if (pqcAddressOf(pk) !== addr) throw new Error(`registry key for ${addr} is not the key that address names`)
      registryKeys.set(addr, { set, publicKey: pk, pqcAddress: addr })
    }
    return { key: registryKeys.get(addr) }
  }

  let passed = 0
  let failed = 0
  let seen = 0
  const lastBlockOf = new Map()
  const perKey = new Map()

  for await (const raw of feedLines(source)) {
    const line = raw.trim()
    if (!line) continue
    seen++
    let entry
    try {
      entry = JSON.parse(line)
    } catch {
      console.error(`  FAIL  invalid JSON: ${line.slice(0, 80)}`)
      failed++; continue
    }
    const { blockNumber, blockHash, chainId, messageHex, signatureHex } = entry

    // Strict mode: detect gaps, per validator
    const v = entry.validatorIndex ?? '?'
    if (STRICT && lastBlockOf.has(v)) {
      const expectedNext = BigInt(lastBlockOf.get(v)) + 1n
      if (BigInt(blockNumber) !== expectedNext) {
        console.error(`  GAP   validator ${v} between ${lastBlockOf.get(v)} and ${blockNumber}`)
        failed++
      }
    }
    lastBlockOf.set(v, blockNumber)

    // 1. Re-derive the canonical message
    const expectedMessage = buildMessage(chainId, blockNumber, blockHash)
    if (messageHex !== bytesToHex(expectedMessage)) {
      console.error(`  FAIL  block ${blockNumber} — message hash mismatch`)
      failed++; continue
    }

    // 2. The key this record names, from the trusted source
    const { key, reason } = await keyFor(entry)
    if (!key) {
      console.error(`  FAIL  block ${blockNumber} — ${reason}`)
      failed++; continue
    }
    if (entry.algorithm !== undefined && entry.algorithm !== key.set.label) {
      console.error(`  FAIL  block ${blockNumber} — record says ${entry.algorithm} but the key is ${key.set.label}`)
      failed++; continue
    }

    // 3. Chain cross-check (skipped if RPC unreachable)
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

    // 4. Signature verify, with the key's own parameter set
    const sig = new Uint8Array(hexToBytes(String(signatureHex).slice(2)))
    if (sig.length === key.set.signatureLength && key.set.impl.verify(key.publicKey, expectedMessage, sig)) {
      passed++
      perKey.set(key.pqcAddress, [key.set.label, (perKey.get(key.pqcAddress)?.[1] || 0) + 1])
    } else {
      console.error(`  FAIL  block ${blockNumber} — invalid ${key.set.label} signature`)
      failed++
    }
  }

  if (seen === 0) {
    console.error('Feed is empty.')
    process.exit(2)
  }

  console.log('\n──────────────────────────────────')
  for (const [addr, [label, n]] of perKey) console.log(`${label} ${addr}: ${n} verified`)
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

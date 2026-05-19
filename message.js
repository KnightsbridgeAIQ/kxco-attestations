/**
 * Canonical message format for KXCO Chain Dilithium3 block attestations.
 * Mirrors docker/attestation/message.js exactly. Do not modify in only one
 * location — the encoding must remain identical between signer and verifier.
 *
 * Message = keccak256( chainId(4 BE) || blockNumber(8 BE) || blockHash(32) )
 */

import { keccak_256 } from '@noble/hashes/sha3'

export function buildMessage(chainId, blockNumber, blockHash) {
  const buf = new Uint8Array(44)  // 4 + 8 + 32
  const view = new DataView(buf.buffer)
  view.setUint32(0, chainId, false)
  view.setBigUint64(4, BigInt(blockNumber), false)
  buf.set(hexToBytes(blockHash.slice(2)), 12)
  return keccak_256(buf)
}

export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

export function bytesToHex(bytes) {
  return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

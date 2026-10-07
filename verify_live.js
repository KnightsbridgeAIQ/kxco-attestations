// Verifies all four validators' current rolling windows end to end, straight
// from the public repository and the chain: the published key history, each
// window, and the chain RPC's block hashes. Nothing is read from KXCO but the
// repository and the public RPC.
//
// Usage: node verify_live.js [--repo KnightsbridgeAIQ/kxco-attestations] [--raw <mirror-url>] [--rpc https://chain.kxco.ai/rpc] [--strict]
//
// Exit 0 when every window verifies, 1 on any failure, 2 if something could
// not be read.

import { spawnSync } from 'child_process'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const args = process.argv.slice(2)
const value = (name, fallback) => (args.includes(name) ? args[args.indexOf(name) + 1] : fallback)
const REPO = value('--repo', 'KnightsbridgeAIQ/kxco-attestations')
const RPC = value('--rpc', 'https://chain.kxco.ai/rpc')
const RAW = value('--raw', `https://raw.githubusercontent.com/${REPO}/main/attestations`)   // or a mirror of that folder
const HERE = dirname(fileURLToPath(import.meta.url))

let worst = 0
for (const n of [1, 2, 3, 4]) {
  const run = spawnSync(process.execPath, [join(HERE, 'verify.js'), `${RAW}/kxco-attestations-node${n}-latest.ndjson`,
    '--keys', `${RAW}/validator-keys.json`, '--rpc', RPC, ...(args.includes('--strict') ? ['--strict'] : [])],
    { encoding: 'utf8' })
  const summary = (run.stdout.match(/^(ML-DSA-\d+ 0x[0-9a-f]{40}: \d+ verified|Verified: .*)$/gm) || []).join('; ')
  console.log(`Validator ${n}: ${run.status === 0 ? 'PASS' : 'FAIL'}  ${summary}`)
  if (run.status !== 0) process.stderr.write(run.stderr)
  worst = Math.max(worst, run.status ?? 2)
}
process.exit(worst)

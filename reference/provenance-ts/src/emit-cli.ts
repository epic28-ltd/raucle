/**
 * Conformance-harness helper: reads JSON requests
 * {"seed_hex":"...","payload":{...}} (one per line) from stdin and writes
 * {"jws":"...","id":"..."} (one per line) to stdout, using the TS
 * reference implementation. See reference/conformance.py.
 */
import { webcrypto } from 'node:crypto'
import { createInterface } from 'node:readline'
import { emit, verify, type ReceiptPayload } from './receipt.js'
import { canonicalEncode } from './canonical.js'

const subtle = webcrypto.subtle

const canonMode = process.argv[2] === '--canon'
const verifyMode = process.argv[2] === '--verify'

function importSeedKey(seedHex: string): Promise<webcrypto.CryptoKey> {
  const seed = Buffer.from(seedHex, 'hex')
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex')
  const pkcs8 = Buffer.concat([prefix, seed])
  return subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign'])
}

// Import the raw 32-byte Ed25519 public key (hex) by wrapping it in the standard
// SubjectPublicKeyInfo DER prefix — the verify-rejection conformance key format.
function importPubKey(hex: string): Promise<webcrypto.CryptoKey> {
  // Exactly 64 hex chars (32 bytes). Buffer.from(.,'hex') silently truncates on
  // odd length / trailing non-hex, so guard first to match Go's strict decode.
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error('bad public_key_hex')
  const raw = Buffer.from(hex, 'hex')
  const prefix = Buffer.from('302a300506032b6570032100', 'hex')
  const spki = Buffer.concat([prefix, raw])
  return subtle.importKey('spki', spki, { name: 'Ed25519' }, false, ['verify'])
}

const rl = createInterface({ input: process.stdin })
for await (const line of rl) {
  if (!line.trim()) continue
  if (verifyMode) {
    // {"jws","public_key_hex"} -> {"verdict":"ACCEPT","id":...} | {"verdict":"REJECT"}.
    // ANY error (malformed line, bad key, bad signature, non-canonical, duplicate
    // key) is REJECT — so JSON.parse lives INSIDE the boundary, not before it.
    let verdict: { verdict: string; id?: string }
    try {
      const req = JSON.parse(line)
      const pub = await importPubKey(req.public_key_hex)
      const r = await verify(req.jws, pub)
      verdict = { verdict: 'ACCEPT', id: r.id }
    } catch {
      verdict = { verdict: 'REJECT' }
    }
    process.stdout.write(JSON.stringify(verdict) + '\n')
    continue
  }
  const req = JSON.parse(line)
  if (canonMode) {
    // Canonicalisation cross-check (key ordering): {"obj": <value>} ->
    // {"hex": "<utf8 hex of canonical bytes>"}.
    const bytes = canonicalEncode(req.obj)
    process.stdout.write(
      JSON.stringify({ hex: Buffer.from(bytes).toString('hex') }) + '\n',
    )
    continue
  }
  const key = await importSeedKey(req.seed_hex)
  const r = await emit(req.payload as ReceiptPayload, key)
  process.stdout.write(JSON.stringify({ jws: r.jws, id: r.id }) + '\n')
}

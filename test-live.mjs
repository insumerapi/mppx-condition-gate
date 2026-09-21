/**
 * Live integration test for mppx-condition-gate.
 * Tests the core flow: DID parsing → proven payer → InsumerAPI call → pass/fail → receipt.
 * Calls the live API and spends attestation credits; not part of `npm test`.
 */

import { strict as assert } from 'node:assert'
import { conditionGate, parseDid, parseSolanaDid, parseXrplDid, clearConditionGateCache } from './dist/index.js'

const API_KEY = process.env.INSUMER_API_KEY
if (!API_KEY) { console.error('Set INSUMER_API_KEY env var'); process.exit(1) }

// Counts /v1/attest calls, so the cache test can show it made none.
let attestCalls = 0
const realFetch = globalThis.fetch
globalThis.fetch = (...args) => { attestCalls++; return realFetch(...args) }

// --- Test 1: DID parsing ---
console.log('--- DID parsing ---')

const evm = parseDid('did:pkh:eip155:8453:0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045')
console.log('EVM DID →', evm)
assert.equal(evm, '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', 'EVM parse failed')

const sol = parseSolanaDid('did:pkh:solana:1:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU')
console.log('Solana DID →', sol)
assert.equal(sol, '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU', 'Solana parse failed')

const xrpl = parseXrplDid('did:pkh:xrpl:0:rN7n3473SaZBCG4dFL83w7p1W9cgZw6iFR')
console.log('XRPL DID →', xrpl)
assert.equal(xrpl, 'rN7n3473SaZBCG4dFL83w7p1W9cgZw6iFR', 'XRPL parse failed')

assert.equal(parseDid('not-a-did'), null, 'Bad DID should return null')
console.log('Bad DID → null ✓')

// --- Test 2: Mock Method.Server + conditionGate with real API call ---
// Free access needs a PROVEN payer (3.x, GHSA-jg6q-3qfh-r9f8): the method's
// non-mutating `validate` hook returns details, and `provenPayer` reads the
// payer from them. `credential.source` is never consulted. The mock stands in
// for mppx's EVM charge, which reports the recovered EIP-3009 signer as `payer`.
console.log('\n--- Live attestation (Vitalik holds USDC dust on Base — prove-any-balance) ---')

const HOLDER = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045'

const mockServer = {
  name: 'evm',
  intent: 'charge',
  schema: {
    credential: { payload: {} },
    request: {},
  },
  // Stands in for signature recovery: here the "proven" payer is the signer
  // the mock was given. A real method derives it from the credential.
  validate: async ({ credential }) => ({ details: { payer: credential.payload.from } }),
  verify: async (_params) => {
    return {
      method: 'evm',
      reference: 'paid:0xabc',
      status: 'success',
      timestamp: new Date().toISOString(),
    }
  },
}

const provenPayer = (details) => details?.payer ?? null

// Each credential is single-use, so every request gets its own EIP-3009 nonce.
let nonceCounter = 0
function credential(from = HOLDER) {
  nonceCounter++
  return {
    challenge: {
      id: `live-${nonceCounter}`,
      intent: 'charge',
      method: 'evm',
      realm: 'test',
      request: {},
      expires: new Date(Date.now() + 300_000).toISOString(),
    },
    payload: {
      type: 'authorization',
      from,
      nonce: '0x' + (Date.now() * 1000 + nonceCounter).toString(16).padStart(64, '0'),
      validBefore: String(Math.floor(Date.now() / 1000) + 300),
      signature: '0x' + 'ab'.repeat(65),
    },
  }
}

const gated = conditionGate(mockServer, {
  apiKey: API_KEY,
  provenPayer,
  conditions: [{
    type: 'token_balance',
    contractAddress: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', // USDC on Base
    chainId: 8453,
    threshold: '0.000001', // prove-any-balance; sent as a decimal string
    label: 'USDC on Base > 0',
  }],
})

const holderResult = await gated.verify({ credential: credential(), request: {} })

console.log('Holder receipt:', JSON.stringify(holderResult, null, 2))
assert.ok(
  holderResult.reference.startsWith('condition-gate:free:ATST-'),
  `Expected condition-gate:free receipt for holder, got: ${holderResult.reference}`,
)
console.log('✓ Proven holder got free access via signed attestation')

// --- Test 3: Cache hit ---
// A fresh credential from the same proven holder reuses the cached pass.
console.log('\n--- Cache hit (no API call) ---')
const callsBefore = attestCalls
const cachedResult = await gated.verify({ credential: credential(), request: {} })
assert.ok(
  cachedResult.reference.startsWith('condition-gate:free:ATST-'),
  `Cached result should still be free, got: ${cachedResult.reference}`,
)
assert.equal(attestCalls, callsBefore, 'Cache hit should not call the API')
console.log('✓ Cache hit returned free access (no API call)')

// --- Test 4: Non-holder (impossibly high threshold) ---
console.log('\n--- Live attestation (impossibly high threshold) ---')
clearConditionGateCache()

const gated2 = conditionGate(mockServer, {
  apiKey: API_KEY,
  provenPayer,
  conditions: [{
    type: 'token_balance',
    contractAddress: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    chainId: 8453,
    threshold: '999999999',
    label: 'USDC on Base >= 999999999',
  }],
})

const nonHolderResult = await gated2.verify({ credential: credential(), request: {} })

console.log('Non-holder receipt:', JSON.stringify(nonHolderResult, null, 2))
assert.equal(nonHolderResult.reference, 'paid:0xabc', 'Expected fallthrough to paid receipt for non-holder')
console.log('✓ Non-holder fell through to payment')

// --- Test 5: No proven payer → always falls through ---
// A qualifying wallet named in credential.source, with no payer proven by
// validate, must pay: this is the behaviour GHSA-jg6q-3qfh-r9f8 fixed.
console.log('\n--- No proven payer (falls through) ---')

const unproven = conditionGate(
  { ...mockServer, validate: async () => ({ details: {} }) },
  { apiKey: API_KEY, provenPayer, conditions: [{
    type: 'token_balance',
    contractAddress: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    chainId: 8453,
    threshold: '0.000001',
  }] },
)
const noPayerResult = await unproven.verify({
  credential: { ...credential(), source: `did:pkh:eip155:8453:${HOLDER}` },
  request: {},
})

assert.equal(noPayerResult.reference, 'paid:0xabc', 'No proven payer should fall through')
console.log('✓ Unproven payer fell through to payment, credential.source ignored')

console.log('\n=== All tests passed ===')

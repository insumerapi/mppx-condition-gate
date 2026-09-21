import test from 'node:test'
import assert from 'node:assert/strict'
import { conditionGate, toDecimalString, clearConditionGateCache } from '../dist/index.js'

const QUALIFYING = '0x1111111111111111111111111111111111111111'

test.beforeEach(() => { clearConditionGateCache() })

// --- toDecimalString ---------------------------------------------------------

test('toDecimalString returns strings trimmed and otherwise unchanged', () => {
  assert.equal(toDecimalString('1000'), '1000')
  assert.equal(toDecimalString('0.005'), '0.005')
  assert.equal(toDecimalString('  250.50 '), '250.50')
  assert.equal(toDecimalString('123456789012345678901234567890.123456789'), '123456789012345678901234567890.123456789')
})

test('toDecimalString writes ordinary numbers as plain decimals', () => {
  assert.equal(toDecimalString(0), '0')
  assert.equal(toDecimalString(-0), '0')
  assert.equal(toDecimalString(1), '1')
  assert.equal(toDecimalString(10), '10')
  assert.equal(toDecimalString(250), '250')
  assert.equal(toDecimalString(0.005), '0.005')
  assert.equal(toDecimalString(1000.5), '1000.5')
  assert.equal(toDecimalString(0.000001), '0.000001')
  assert.equal(toDecimalString(123456789012345680000), '123456789012345680000')
})

test('toDecimalString never emits exponent notation', () => {
  assert.equal(String(1e-7), '1e-7', 'the case the helper exists for')
  assert.equal(toDecimalString(1e-7), '0.0000001')
  assert.equal(toDecimalString(1.5e-7), '0.00000015')
  assert.equal(toDecimalString(1.234e-10), '0.0000000001234')
  assert.equal(toDecimalString(5e-324), '0.' + '0'.repeat(323) + '5')
  assert.equal(String(1e21), '1e+21')
  assert.equal(toDecimalString(1e21), '1' + '0'.repeat(21))
  assert.equal(toDecimalString(1.5e21), '15' + '0'.repeat(20))
  assert.equal(toDecimalString(1.2345e25), '12345' + '0'.repeat(21))
  assert.equal(toDecimalString(-1e-7), '-0.0000001')
  assert.equal(toDecimalString(-1e21), '-1' + '0'.repeat(21))
  for (const n of [1e-7, 3.3e-9, 1e21, 7.25e30, Number.MAX_VALUE, Number.MIN_VALUE, 0.1 + 0.2]) {
    const s = toDecimalString(n)
    assert.match(s, /^-?\d+(\.\d+)?$/, `${n} -> ${s}`)
    assert.equal(Number(s), n, 'the decimal string reads back as the same number')
  }
})

test('toDecimalString throws for NaN, Infinity and non-quantities', () => {
  for (const bad of [NaN, Infinity, -Infinity, undefined, null, {}, 10n]) {
    assert.throws(() => toDecimalString(bad), /decimal string or a finite number/)
  }
})

// --- Request bodies ----------------------------------------------------------

/** Stub /v1/attest and capture the JSON body of each call. */
function captureAttest() {
  const bodies = []
  globalThis.fetch = async (_url, init) => {
    bodies.push(JSON.parse(init.body))
    return {
      ok: true,
      status: 200,
      json: async () => ({
        ok: true,
        data: { attestation: { id: 'ATST-TEST', pass: true, results: [{ met: true }] } },
      }),
    }
  }
  return bodies
}

function makeServer() {
  const paidReceipt = { method: 'test', reference: 'PAID', status: 'success', timestamp: 'x' }
  return {
    name: 'test',
    verify: async () => paidReceipt,
    validate: async () => ({ details: { payer: QUALIFYING } }),
    broadcast: async () => paidReceipt,
  }
}

let counter = 0
function cred() {
  counter++
  return {
    challenge: { id: `body-challenge-${counter}`, expires: new Date(Date.now() + 300_000).toISOString() },
    payload: {
      type: 'authorization',
      from: QUALIFYING,
      nonce: '0x' + (0xb0d70000 + counter).toString(16).padStart(64, '0'),
      validBefore: String(Math.floor(Date.now() / 1000) + 300),
      signature: `0x${counter.toString(16).padStart(130, 'b')}`,
    },
  }
}

async function bodyFor(conditions) {
  const bodies = captureAttest()
  const gated = conditionGate(makeServer(), { apiKey: 'k', conditions, provenPayer: (d) => d.payer })
  const receipt = await gated.verify({ credential: cred() })
  assert.ok(String(receipt.reference).startsWith('condition-gate:free:'), 'the attest call was made and passed')
  assert.equal(bodies.length, 1)
  return bodies[0]
}

test('ratio_to_amount sends multiple and amount as decimal strings (numbers given)', async () => {
  const body = await bodyFor([
    { type: 'ratio_to_amount', contractAddress: 'native', chainId: 8453, multiple: 10, amount: 250, label: 'x' },
  ])
  assert.equal(body.wallet, QUALIFYING)
  assert.deepEqual(body.conditions, [
    { type: 'ratio_to_amount', contractAddress: 'native', chainId: 8453, multiple: '10', amount: '250', label: 'x' },
  ])
})

test('ratio_to_amount passes strings through and expands small numbers', async () => {
  const asStrings = await bodyFor([
    { type: 'ratio_to_amount', contractAddress: '0xTOKEN', chainId: 1, multiple: '2.5', amount: '0.01' },
  ])
  assert.deepEqual(asStrings.conditions, [
    { type: 'ratio_to_amount', contractAddress: '0xTOKEN', chainId: 1, multiple: '2.5', amount: '0.01' },
  ])

  const small = await bodyFor([
    { type: 'ratio_to_amount', contractAddress: 'native', chainId: 1, multiple: 10, amount: 1e-7 },
  ])
  assert.equal(small.conditions[0].amount, '0.0000001')
  assert.equal(small.conditions[0].multiple, '10')
})

test('ratio_to_supply sends minFraction as a decimal string', async () => {
  const fromNumber = await bodyFor([
    { type: 'ratio_to_supply', contractAddress: '0xUNI', chainId: 1, minFraction: 0.005, label: 'y' },
  ])
  assert.deepEqual(fromNumber.conditions, [
    { type: 'ratio_to_supply', contractAddress: '0xUNI', chainId: 1, minFraction: '0.005', label: 'y' },
  ])

  const fromString = await bodyFor([
    { type: 'ratio_to_supply', contractAddress: '0xUNI', chainId: 1, minFraction: '0.005' },
  ])
  assert.equal(fromString.conditions[0].minFraction, '0.005')

  const tiny = await bodyFor([
    { type: 'ratio_to_supply', contractAddress: '0xUNI', chainId: 1, minFraction: 2e-8 },
  ])
  assert.equal(tiny.conditions[0].minFraction, '0.00000002')
})

test('token_balance threshold is a decimal string, and decimals is sent only when given', async () => {
  const defaulted = await bodyFor([{ type: 'token_balance', contractAddress: '0xTOKEN', chainId: 8453 }])
  assert.deepEqual(defaulted.conditions, [
    { type: 'token_balance', contractAddress: '0xTOKEN', chainId: 8453, threshold: '1' },
  ])

  const numeric = await bodyFor([{ type: 'token_balance', contractAddress: 'native', chainId: 1, threshold: 1e-7 }])
  assert.equal(numeric.conditions[0].threshold, '0.0000001')
  assert.ok(!('decimals' in numeric.conditions[0]), 'no decimals unless the caller supplies one')

  const big = await bodyFor([{ type: 'token_balance', contractAddress: '0xTOKEN', chainId: 1, threshold: 1e21 }])
  assert.equal(big.conditions[0].threshold, '1' + '0'.repeat(21))
})

test('a quantity that is not a finite number is reported when the gate is created', () => {
  for (const conditions of [
    [{ type: 'ratio_to_amount', contractAddress: 'native', chainId: 1, multiple: NaN, amount: 1 }],
    [{ type: 'ratio_to_amount', contractAddress: 'native', chainId: 1, multiple: 1, amount: Infinity }],
    [{ type: 'ratio_to_supply', contractAddress: '0xUNI', chainId: 1, minFraction: NaN }],
    [{ type: 'token_balance', contractAddress: '0xTOKEN', chainId: 1, threshold: NaN }],
  ]) {
    assert.throws(
      () => conditionGate(makeServer(), { apiKey: 'k', conditions, provenPayer: (d) => d.payer }),
      /decimal string or a finite number/,
    )
  }
})

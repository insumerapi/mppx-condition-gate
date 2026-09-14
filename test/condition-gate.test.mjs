import test from 'node:test'
import assert from 'node:assert/strict'
import { conditionGate, normalizeProvenPayer, clearConditionGateCache } from '../dist/index.js'

const QUALIFYING = '0x1111111111111111111111111111111111111111'
const CONDITIONS = [{ type: 'token_balance', contractAddress: '0xTOKEN', chainId: 8453 }]

/** Stub /v1/attest. `met` decides pass/fail; `fail` makes the call error. */
function stubAttest({ met = true, fail = false } = {}) {
  globalThis.fetch = async () => {
    if (fail) return { ok: false, status: 500, json: async () => ({ ok: false, error: { message: 'boom' } }) }
    return {
      ok: true,
      status: 200,
      json: async () => ({
        ok: true,
        data: { attestation: { id: 'ATST-TEST', pass: met, results: [{ met }] } },
      }),
    }
  }
}

/** A method server. `validate` present unless `legacy`. */
function makeServer({ legacy = false, details = { payer: QUALIFYING } } = {}) {
  const calls = { verify: 0, broadcast: 0, validate: 0 }
  const paidReceipt = { method: 'test', reference: 'PAID', status: 'success', timestamp: 'x' }
  const server = {
    name: 'test',
    verify: async () => { calls.verify++; return paidReceipt },
  }
  if (!legacy) {
    server.validate = async () => { calls.validate++; return { details } }
    server.broadcast = async () => { calls.broadcast++; return paidReceipt }
  }
  return { server, calls }
}

let credentialCounter = 0
const nonceHex = (n) => '0x' + n.toString(16).padStart(64, '0')
const inSeconds = (sec) => String(Math.floor(Date.now() / 1000) + sec)

/**
 * A credential shaped like mppx's EVM charge hands the gate: an EIP-3009
 * authorization with a unique nonce, inside a challenge.
 */
function cred({ challengeId, expires, payload, source, from = QUALIFYING, nonce, validBefore } = {}) {
  credentialCounter++
  return {
    challenge: {
      id: challengeId ?? `challenge-${credentialCounter}`,
      expires: expires ?? new Date(Date.now() + 300_000).toISOString(),
    },
    payload: payload ?? {
      type: 'authorization',
      from,
      nonce: nonce ?? nonceHex(credentialCounter),
      validBefore: validBefore ?? inSeconds(300),
      signature: `0x${credentialCounter.toString(16).padStart(130, 'a')}`,
    },
    ...(source ? { source } : {}),
  }
}

const paid = (r) => r.reference === 'PAID'
const free = (r) => typeof r.reference === 'string' && r.reference.startsWith('condition-gate:free:')

test.beforeEach(() => { clearConditionGateCache() })

// --- The reported vulnerability (GHSA-jg6q-3qfh-r9f8) -----------------------

test('REGRESSION: a qualifying wallet named in credential.source with no ownership proof does NOT get a free receipt', async () => {
  stubAttest({ met: true })
  // No provenPayer resolver configured — the pre-3.0.0 gate would have read
  // credential.source here and granted free access.
  const { server, calls } = makeServer()
  const gated = conditionGate(server, { apiKey: 'k', conditions: CONDITIONS })

  const result = await gated.verify({
    credential: cred({ source: `did:pkh:eip155:8453:${QUALIFYING}` }),
  })

  assert.ok(paid(result), 'must fall through to the paid path')
  assert.equal(calls.verify, 1, 'the payment verifier must run')
})

test('REGRESSION: credential.source is never consulted even when a resolver exists', async () => {
  stubAttest({ met: true })
  // Resolver sees only `details`; details carry NO payer, so no free access —
  // despite a qualifying wallet sitting in credential.source.
  const { server, calls } = makeServer({ details: {} })
  const gated = conditionGate(server, {
    apiKey: 'k',
    conditions: CONDITIONS,
    provenPayer: (details) => details?.payer ?? null,
  })

  const result = await gated.verify({
    credential: cred({ source: `did:pkh:eip155:8453:${QUALIFYING}` }),
  })

  assert.ok(paid(result))
  assert.equal(calls.verify, 1)
})

test('the resolver receives ONLY validation details — not the credential', async () => {
  stubAttest({ met: true })
  let seen = 'unset'
  const { server } = makeServer({ details: { payer: QUALIFYING, marker: 'DETAILS' } })
  const gated = conditionGate(server, {
    apiKey: 'k',
    conditions: CONDITIONS,
    provenPayer: (arg) => { seen = arg; return arg.payer },
  })

  await gated.verify({ credential: cred({ source: `did:pkh:eip155:8453:${QUALIFYING}` }) })

  assert.equal(seen.marker, 'DETAILS')
  assert.equal(seen.credential, undefined, 'resolver must not receive the credential')
  assert.equal(seen.source, undefined, 'resolver must not receive the declared source')
})

// --- Fail-closed paths ------------------------------------------------------

test('no validate hook (legacy verify-only method) never grants free access', async () => {
  stubAttest({ met: true })
  const { server, calls } = makeServer({ legacy: true })
  const gated = conditionGate(server, {
    apiKey: 'k',
    conditions: CONDITIONS,
    provenPayer: () => QUALIFYING,
  })

  const result = await gated.verify({ credential: cred({ source: 'x' }) })
  assert.ok(paid(result), 'no safe pre-check exists → paid path')
  assert.equal(calls.verify, 1)
})

test('resolver returning null → paid path', async () => {
  stubAttest({ met: true })
  const { server, calls } = makeServer()
  const gated = conditionGate(server, {
    apiKey: 'k', conditions: CONDITIONS, provenPayer: () => null,
  })
  assert.ok(paid(await gated.verify({ credential: cred() })))
  assert.equal(calls.verify, 1)
})

test('resolver throwing → paid path', async () => {
  stubAttest({ met: true })
  const { server } = makeServer()
  const gated = conditionGate(server, {
    apiKey: 'k', conditions: CONDITIONS,
    provenPayer: () => { throw new Error('nope') },
  })
  assert.ok(paid(await gated.verify({ credential: cred() })))
})

test('validate throwing → paid path', async () => {
  stubAttest({ met: true })
  const { server } = makeServer()
  server.validate = async () => { throw new Error('bad credential') }
  const gated = conditionGate(server, {
    apiKey: 'k', conditions: CONDITIONS, provenPayer: () => QUALIFYING,
  })
  assert.ok(paid(await gated.verify({ credential: cred() })))
})

test('attestation API error → paid path (fail closed)', async () => {
  stubAttest({ fail: true })
  const { server } = makeServer()
  const gated = conditionGate(server, {
    apiKey: 'k', conditions: CONDITIONS, provenPayer: (d) => d.payer,
  })
  assert.ok(paid(await gated.verify({ credential: cred() })))
})

test('conditions not met → paid path', async () => {
  stubAttest({ met: false })
  const { server } = makeServer()
  const gated = conditionGate(server, {
    apiKey: 'k', conditions: CONDITIONS, provenPayer: (d) => d.payer,
  })
  assert.ok(paid(await gated.verify({ credential: cred() })))
})

// --- The happy path still works --------------------------------------------

test('proven payer + conditions met → free receipt, payment never runs', async () => {
  stubAttest({ met: true })
  const { server, calls } = makeServer()
  const gated = conditionGate(server, {
    apiKey: 'k', conditions: CONDITIONS, provenPayer: (d) => d.payer,
  })

  const result = await gated.verify({ credential: cred() })
  assert.ok(free(result), `expected free receipt, got ${result.reference}`)
  assert.equal(calls.verify, 0, 'payment must NOT run')
  assert.equal(calls.validate, 1)
})

test('broadcast is gated too, and settlement is skipped on free access', async () => {
  stubAttest({ met: true })
  const { server, calls } = makeServer()
  const gated = conditionGate(server, {
    apiKey: 'k', conditions: CONDITIONS, provenPayer: (d) => d.payer,
  })

  const result = await gated.broadcast({ credential: cred() })
  assert.ok(free(result))
  assert.equal(calls.broadcast, 0, 'settlement must NOT run')
})

test('cached pass still requires a proven payer on the later request', async () => {
  stubAttest({ met: true })
  const warm = makeServer()
  const gatedWarm = conditionGate(warm.server, {
    apiKey: 'k', conditions: CONDITIONS, provenPayer: (d) => d.payer,
  })
  assert.ok(free(await gatedWarm.verify({ credential: cred() })), 'warm the cache')

  // Same wallet is now cached as passing. A request that proves nothing must
  // still take the paid path.
  const cold = makeServer({ details: {} })
  const gatedCold = conditionGate(cold.server, {
    apiKey: 'k', conditions: CONDITIONS, provenPayer: (d) => d?.payer ?? null,
  })
  const result = await gatedCold.verify({
    credential: cred({ source: `did:pkh:eip155:8453:${QUALIFYING}` }),
  })
  assert.ok(paid(result), 'cache must not be reachable without a proven payer')
  assert.equal(cold.calls.verify, 1)
})

// --- Single-use credentials ------------------------------------------------

const rejected = async (promise) => {
  try { await promise } catch (e) { return e }
  return null
}
const gateFor = (server, extra = {}) =>
  conditionGate(server, { apiKey: 'k', conditions: CONDITIONS, provenPayer: (d) => d.payer, ...extra })

test('REGRESSION: a credential that got free access cannot be presented again', async () => {
  stubAttest({ met: true })
  const { server, calls } = makeServer()
  const gated = gateFor(server)
  const captured = cred()

  assert.ok(free(await gated.verify({ credential: captured })), 'first presentation is free')
  for (let i = 0; i < 3; i++) {
    const err = await rejected(gated.verify({ credential: captured }))
    assert.ok(err, `repeat ${i + 1} must be refused`)
    assert.match(err.message, /already been presented/)
  }
  assert.equal(calls.verify, 0, 'a repeat must not settle the holder\'s authorization either')
})

test('REGRESSION: a repeat is refused on broadcast too, and nothing settles', async () => {
  stubAttest({ met: true })
  const { server, calls } = makeServer()
  const gated = gateFor(server)
  const captured = cred()
  assert.ok(free(await gated.broadcast({ credential: captured })))
  assert.ok(await rejected(gated.broadcast({ credential: captured })))
  assert.equal(calls.broadcast, 0)
})

test('REGRESSION: concurrent presentations of one credential yield exactly one free receipt', async () => {
  stubAttest({ met: true })
  const gated = gateFor(makeServer().server)
  const captured = cred()
  const results = await Promise.allSettled(Array.from({ length: 8 }, () => gated.verify({ credential: captured })))
  assert.equal(results.filter((r) => r.status === 'fulfilled' && free(r.value)).length, 1)
  assert.equal(results.filter((r) => r.status === 'rejected').length, 7)
})

test('REGRESSION: the same authorization is refused under a rebuilt challenge, re-encoded signature, or re-cased hex', async () => {
  stubAttest({ met: true })
  const gated = gateFor(makeServer().server)
  const nonce = nonceHex(0xabcdef)
  assert.ok(free(await gated.verify({ credential: cred({ nonce }) })))
  const variant = cred({ nonce: nonce.toUpperCase().replace('0X', '0x') })
  variant.payload.from = QUALIFYING.toLowerCase()
  variant.payload.signature = '0x' + 'b'.repeat(130)
  assert.ok(await rejected(gated.verify({ credential: variant })))
})

test('two users whose credentials share one challenge id both get free access', async () => {
  stubAttest({ met: true })
  const other = '0x2222222222222222222222222222222222222222'
  const { server } = makeServer()
  server.validate = async (params) => ({ details: { payer: params.credential.payload.from } })
  const gated = gateFor(server)
  assert.ok(free(await gated.verify({ credential: cred({ challengeId: 'same-ms' }) })))
  assert.ok(free(await gated.verify({ credential: cred({ challengeId: 'same-ms', from: other }) })))
})

test('a repeated credential does not block a different credential on the same challenge', async () => {
  stubAttest({ met: true })
  const gated = gateFor(makeServer().server)
  const old = cred({ challengeId: 'shared' })
  assert.ok(free(await gated.verify({ credential: old })))
  assert.ok(await rejected(gated.verify({ credential: { ...old, challenge: { ...old.challenge, id: 'busy' } } })))
  assert.ok(free(await gated.verify({ credential: cred({ challengeId: 'busy' }) })), 'a fresh credential on that challenge is unaffected')
})

test('REGRESSION: a credential whose payment settled cannot come back for free access', async () => {
  stubAttest({ met: false })
  const { server, calls } = makeServer()
  const gated = gateFor(server, { cacheTtlSeconds: 0 })
  const captured = cred()
  assert.ok(paid(await gated.verify({ credential: captured })))

  stubAttest({ met: true })
  assert.ok(await rejected(gated.verify({ credential: captured })), 'settled credential must be refused')
  assert.equal(calls.verify, 1, 'and must not settle a second time')
})

test('a payment that fails is not recorded, so the same credential can be retried', async () => {
  stubAttest({ met: false })
  const { server, calls } = makeServer()
  let failNext = true
  const settle = server.verify
  server.verify = async (p) => { if (failNext) { failNext = false; calls.verify++; throw new Error('facilitator timeout') } return settle(p) }
  const gated = gateFor(server)
  const captured = cred()
  assert.ok(await rejected(gated.verify({ credential: captured })), 'first attempt fails in settlement')
  assert.ok(paid(await gated.verify({ credential: captured })), 'the retry settles')
  assert.equal(calls.verify, 2)
})

test('hash and transaction credentials never get free access; their method handles replay', async () => {
  stubAttest({ met: true })
  for (const payload of [{ type: 'hash', hash: '0x' + 'ab'.repeat(32) }, { type: 'transaction', signature: '0x76f8' }]) {
    const { server, calls } = makeServer()
    const gated = gateFor(server)
    const c = cred({ payload })
    assert.ok(paid(await gated.verify({ credential: c })))
    assert.ok(paid(await gated.verify({ credential: c })), 'the gate records nothing it cannot identify')
    assert.equal(calls.verify, 2)
  }
})

test('a Tempo proof gets free access once per challenge and payer; a repeat goes to the method', async () => {
  stubAttest({ met: true })
  const other = '0x3333333333333333333333333333333333333333'
  const { server, calls } = makeServer()
  server.validate = async (params) => ({ details: { payer: params.credential.source } })
  const gated = gateFor(server)
  const proof = (id, who, sig) => ({ challenge: { id, expires: new Date(Date.now() + 300_000).toISOString() }, payload: { type: 'proof', signature: sig }, source: who })
  assert.ok(free(await gated.verify({ credential: proof('c1', QUALIFYING, '0x01') })))
  // Proofs only exist on zero-amount routes, so a repeat is not refused: the method decides.
  assert.ok(paid(await gated.verify({ credential: proof('c1', QUALIFYING, '0x02') })), 'repeat is not free, and not refused')
  assert.equal(calls.verify, 1)
  assert.ok(free(await gated.verify({ credential: proof('c1', other, '0x03') })), 'another payer on the same challenge is unaffected')
})

test('credentials valid for longer than maxCredentialLifetimeSeconds take the paid path', async () => {
  stubAttest({ met: true })
  const longLived = () => cred({ validBefore: inSeconds(10 * 365 * 86400) })
  const { server, calls } = makeServer()
  assert.ok(paid(await gateFor(server).verify({ credential: longLived() })))
  assert.equal(calls.verify, 1)
  assert.ok(free(await gateFor(makeServer().server, { maxCredentialLifetimeSeconds: 11 * 365 * 86400 }).verify({ credential: longLived() })))
})

test('a credential with no readable expiry or identity gets no free access', async () => {
  stubAttest({ met: true })
  const { server, calls } = makeServer()
  const gated = gateFor(server)
  assert.ok(paid(await gated.verify({ credential: {} })))
  assert.ok(paid(await gated.verify({ credential: { challenge: { id: 'x' }, payload: { type: 'authorization', from: QUALIFYING, nonce: '0x01' } } })))
  assert.equal(calls.verify, 2)
})

test('a shared replayStore stops repeats across instances; an update-only store works', async () => {
  stubAttest({ met: true })
  const data = new Map()
  const updateOnly = {
    async update(key, fn) {
      const change = fn(data.has(key) ? data.get(key) : null)
      if (change.op === 'set') data.set(key, change.value)
      if (change.op === 'delete') data.delete(key)
      return change.result
    },
  }
  const a = gateFor(makeServer().server, { replayStore: updateOnly })
  const b = gateFor(makeServer().server, { replayStore: updateOnly })
  const captured = cred()
  assert.ok(free(await a.verify({ credential: captured })))
  assert.ok(await rejected(b.verify({ credential: captured })), 'instance B must refuse what instance A accepted')
  assert.equal([...data.values()][0].type, 'mppx:replay', 'markers match mppx Store.tryClaim')
})

test('a store that cannot record takes the paid path; a store with no claim method is rejected at setup', async () => {
  stubAttest({ met: true })
  const broken = { tryClaim: async () => { throw new Error('store down') } }
  const { server, calls } = makeServer()
  assert.ok(paid(await gateFor(server, { replayStore: broken }).verify({ credential: cred() })))
  assert.equal(calls.verify, 1)
  assert.throws(() => gateFor(makeServer().server, { replayStore: { get: () => null } }), /replayStore/)
})

test('REGRESSION: a copy presented while its payment is still settling is refused', async () => {
  stubAttest({ met: false })
  const { server, calls } = makeServer()
  let letSettle
  let entered
  const settling = new Promise((r) => { letSettle = r })
  const reachedSettlement = new Promise((r) => { entered = r })
  const settle = server.verify
  server.verify = async (p) => { entered(); await settling; return settle(p) }
  const gated = gateFor(server, { cacheTtlSeconds: 0 })
  const captured = cred()

  const first = gated.verify({ credential: captured })
  await reachedSettlement
  stubAttest({ met: true })
  assert.ok(await rejected(gated.verify({ credential: captured })), 'the in-flight copy must not get free access')
  letSettle()
  assert.ok(paid(await first))
  assert.equal(calls.verify, 1)
})

test('a failed payment is released in a caller store too, so the retry settles and then is spent', async () => {
  stubAttest({ met: false })
  const data = new Map()
  const updateOnly = {
    async update(key, fn) {
      const change = fn(data.has(key) ? data.get(key) : null)
      if (change.op === 'set') data.set(key, change.value)
      if (change.op === 'delete') data.delete(key)
      return change.result
    },
  }
  const { server } = makeServer()
  let attempts = 0
  server.verify = async () => {
    attempts++
    if (attempts === 1) throw new Error('facilitator timeout')
    return { method: 'test', reference: 'PAID', status: 'success', timestamp: 'x' }
  }
  const gated = gateFor(server, { replayStore: updateOnly })
  const captured = cred()
  assert.ok(await rejected(gated.verify({ credential: captured })))
  assert.equal(data.size, 0, 'the failed payment was released')
  assert.ok(paid(await gated.verify({ credential: captured })))
  assert.ok(await rejected(gated.verify({ credential: captured })), 'a settled credential is spent')
  assert.equal(attempts, 2)
})

test('the default store limits how much of it one wallet can hold', async () => {
  stubAttest({ met: true })
  const other = '0x4444444444444444444444444444444444444444'
  const { server } = makeServer()
  server.validate = async (params) => ({ details: { payer: params.credential.payload.from } })
  const gated = gateFor(server)
  let freeCount = 0
  for (let i = 0; i < 5000; i++) if (free(await gated.verify({ credential: cred() }))) freeCount++
  assert.equal(freeCount, 5000)
  assert.ok(paid(await gated.verify({ credential: cred() })), 'past its share, the wallet pays')
  assert.ok(free(await gated.verify({ credential: cred({ from: other }) })), 'other wallets still get free access')
})

test('an authorization is bounded by its own validBefore, not the challenge expiry', async () => {
  stubAttest({ met: true })
  const longChallenge = new Date(Date.now() + 2 * 3600_000).toISOString()
  assert.ok(free(await gateFor(makeServer().server).verify({ credential: cred({ expires: longChallenge }) })))
  const { server, calls } = makeServer()
  assert.ok(paid(await gateFor(server).verify({ credential: cred({ validBefore: inSeconds(2 * 3600) }) })))
  assert.equal(calls.verify, 1)
})

test('a store whose get returns false for missing keys does not block traffic', async () => {
  stubAttest({ met: true })
  const data = new Map()
  const store = {
    get: async (k) => (data.has(k) ? data.get(k) : false),
    tryClaim: (k, exp) => {
      const c = data.get(k)
      if (c && c.expires > Date.now()) return false
      data.set(k, { expires: exp, type: 'mppx:replay' })
      return true
    },
  }
  const gated = gateFor(makeServer().server, { replayStore: store })
  const captured = cred()
  assert.ok(free(await gated.verify({ credential: captured })))
  assert.ok(await rejected(gated.verify({ credential: captured })))
})

test('REGRESSION: a settled authorization stays recorded until it expires, even past the lifetime cap', async () => {
  stubAttest({ met: false })
  const { server, calls } = makeServer()
  const gated = gateFor(server, { cacheTtlSeconds: 0 })
  const captured = cred({ validBefore: inSeconds(7200) })
  assert.ok(paid(await gated.verify({ credential: captured })), 'over the cap, so it pays')
  const realNow = Date.now
  const later = realNow() + 3665_000
  try {
    Date.now = () => later
    stubAttest({ met: true })
    assert.ok(await rejected(gated.verify({ credential: captured })), 'still refused once its remaining validity is under the cap')
  } finally {
    Date.now = realNow
  }
  assert.equal(calls.verify, 1)
})

test('a Tempo proof that takes the paid path is not recorded, so the method decides repeats', async () => {
  stubAttest({ met: false })
  const { server, calls } = makeServer()
  server.validate = async (params) => ({ details: { payer: params.credential.source } })
  const gated = gateFor(server)
  const proof = {
    challenge: { id: 'zero-amount', expires: new Date(Date.now() + 300_000).toISOString() },
    payload: { type: 'proof', signature: '0x01' },
    source: QUALIFYING,
  }
  assert.ok(paid(await gated.verify({ credential: proof })))
  assert.ok(paid(await gated.verify({ credential: proof })))
  assert.equal(calls.verify, 2)
})

test('maxCredentialLifetimeSeconds must be a finite number of seconds', () => {
  for (const bad of [NaN, Infinity, -1, '600']) {
    assert.throws(() => gateFor(makeServer().server, { maxCredentialLifetimeSeconds: bad }), /maxCredentialLifetimeSeconds/)
  }
})

test('the default lifetime cap is ten minutes', async () => {
  stubAttest({ met: true })
  const { server, calls } = makeServer()
  assert.ok(paid(await gateFor(server).verify({ credential: cred({ validBefore: inSeconds(900) }) })))
  assert.equal(calls.verify, 1)
  assert.ok(free(await gateFor(makeServer().server).verify({ credential: cred({ validBefore: inSeconds(590) }) })))
})

// --- normalizeProvenPayer ---------------------------------------------------

test('normalizeProvenPayer resolves DIDs and bare EVM, rejects the ambiguous', () => {
  assert.deepEqual(normalizeProvenPayer(`did:pkh:eip155:8453:${QUALIFYING}`), { address: QUALIFYING, type: 'evm' })
  assert.deepEqual(normalizeProvenPayer('did:pkh:solana:mainnet:SoL123'), { address: 'SoL123', type: 'solana' })
  assert.deepEqual(normalizeProvenPayer('did:pkh:xrpl:0:rABC'), { address: 'rABC', type: 'xrpl' })
  assert.deepEqual(normalizeProvenPayer('did:pkh:bip122:0:bc1q'), { address: 'bc1q', type: 'bitcoin' })
  assert.deepEqual(normalizeProvenPayer(QUALIFYING), { address: QUALIFYING, type: 'evm' })
  assert.deepEqual(normalizeProvenPayer({ address: 'SoL123', type: 'solana' }), { address: 'SoL123', type: 'solana' })

  assert.equal(normalizeProvenPayer(null), null)
  assert.equal(normalizeProvenPayer(undefined), null)
  assert.equal(normalizeProvenPayer(''), null)
  assert.equal(normalizeProvenPayer('SoL123'), null, 'bare non-EVM is ambiguous → reject')
  assert.equal(normalizeProvenPayer({ address: 'x' }), null, 'object form needs an explicit type')
})

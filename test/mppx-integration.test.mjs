// End-to-end tests through the real mppx server handler and client, with EVM
// charge credentials signed by real viem accounts. InsumerAPI is stubbed and
// settlement is simulated with an in-memory nonce set, so nothing leaves the
// machine.
import test from 'node:test'
import assert from 'node:assert/strict'
import { Mppx as ServerMppx, evm as sevm, Store, Expires } from 'mppx/server'
import { Mppx as ClientMppx, evm as cevm } from 'mppx/client'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { conditionGate, clearConditionGateCache } from '../dist/index.js'

const URL_ = 'https://api.example.com/premium'
const RECIPIENT = '0x742d35Cc6634c0532925a3b844bC9e7595F8fE00'
const CONDITIONS = [{ type: 'token_balance', contractAddress: '0x' + '22'.repeat(20), chainId: 8453, threshold: '1' }]
const SECRET_A = 'a'.repeat(44)
const SECRET_B = 'b'.repeat(44)

const qualifying = new Set()
const realFetch = globalThis.fetch

test.before(() => {
  globalThis.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input.url
    if (!url.startsWith('https://api.insumermodel.com/')) throw new Error(`unexpected network call: ${url}`)
    const met = qualifying.has(String(JSON.parse(init.body).wallet).toLowerCase())
    return new Response(
      JSON.stringify({ ok: true, data: { attestation: { id: 'ATST-IT', pass: met, results: [{ met }] } } }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    )
  }
})
test.after(() => { globalThis.fetch = realFetch })
test.beforeEach(() => { clearConditionGateCache(); qualifying.clear() })

/** A merchant route. `chain` is the shared nonce state, so two servers can see one chain. */
function route({ gated = true, chain = new Set(), failSettleOnce = false, x402MaxTimeoutSeconds, replayStore, secretKey = SECRET_A, expires } = {}) {
  const counters = { settles: 0, settleAttempts: 0 }
  let failNext = failSettleOnce
  const method = sevm.charge({
    currency: sevm.assets.base.USDC,
    recipient: RECIPIENT,
    ...(x402MaxTimeoutSeconds ? { x402: { maxTimeoutSeconds: x402MaxTimeoutSeconds } } : {}),
    settle: async ({ payload }) => {
      counters.settleAttempts++
      if (failNext) { failNext = false; throw new Error('facilitator timeout') }
      if (chain.has(payload.nonce)) throw new Error('authorization already used')
      chain.add(payload.nonce)
      counters.settles++
      return { reference: '0xsettled' }
    },
  })
  const m = gated
    ? conditionGate(method, {
      apiKey: 'k',
      conditions: CONDITIONS,
      provenPayer: (d) => d?.payer ?? null,
      cacheTtlSeconds: 0,
      ...(replayStore ? { replayStore } : {}),
    })
    : method
  const mppx = ServerMppx.create({ methods: [m], secretKey })
  const handle = async (headers = {}) => {
    const r = await mppx.charge({ amount: '0.01', ...(expires ? { expires } : {}) })(new Request(URL_, { headers }))
    return r.status === 402 ? { status: 402, challenge: r.challenge } : { status: 200 }
  }
  return { handle, counters, mppx }
}

function wallet() {
  const account = privateKeyToAccount(generatePrivateKey())
  const client = ClientMppx.create({ polyfill: false, methods: [cevm.charge({ account, currencies: [sevm.assets.base.USDC] })] })
  return {
    address: account.address,
    qualify() { qualifying.add(account.address.toLowerCase()) },
    async native(challengeResponse) {
      return { Authorization: await client.createCredential(challengeResponse) }
    },
    async x402(challengeResponse) {
      const h = new Headers()
      h.set('PAYMENT-REQUIRED', challengeResponse.headers.get('PAYMENT-REQUIRED'))
      const credential = await client.createCredential(new Response(null, { status: 402, headers: h }))
      assert.ok(!credential.startsWith('Payment '), 'client must sign an x402 payload')
      return { 'PAYMENT-SIGNATURE': credential }
    },
  }
}

const statuses = async (handle, headers, n) => {
  const out = []
  for (let i = 0; i < n; i++) out.push((await handle(headers)).status)
  return out
}

test('control: without the gate, mppx refuses a repeated credential once it settles', async () => {
  const r = route({ gated: false })
  const w = wallet()
  const headers = await w.native((await r.handle()).challenge)
  assert.deepEqual(await statuses(r.handle, headers, 3), [200, 402, 402])
  assert.equal(r.counters.settles, 1)
})

test('native EVM credential: free once, every repeat refused, nothing settles', async () => {
  const r = route()
  const w = wallet()
  w.qualify()
  const headers = await w.native((await r.handle()).challenge)
  assert.deepEqual(await statuses(r.handle, headers, 4), [200, 402, 402, 402])
  assert.equal(r.counters.settleAttempts, 0)
})

test('x402 credential: free once, refused on repeat and on a second server sharing the store', async () => {
  const replayStore = Store.memory()
  const chain = new Set()
  const a = route({ replayStore, chain })
  const b = route({ replayStore, chain, secretKey: SECRET_B })
  const w = wallet()
  w.qualify()
  const headers = await w.x402((await a.handle()).challenge)
  assert.deepEqual(await statuses(a.handle, headers, 2), [200, 402])
  assert.equal((await b.handle(headers)).status, 402, 'a different secret key does not reopen it')
  assert.equal(a.counters.settleAttempts + b.counters.settleAttempts, 0)
})

test('two qualifying wallets signing against one challenge both get free access', async () => {
  const r = route()
  const challenge = (await r.handle()).challenge
  const alice = wallet()
  const bob = wallet()
  alice.qualify()
  bob.qualify()
  const aliceHeaders = await alice.native(challenge.clone())
  const bobHeaders = await bob.native(challenge.clone())
  assert.equal((await r.handle(aliceHeaders)).status, 200)
  assert.equal((await r.handle(bobHeaders)).status, 200)
  assert.equal((await r.handle(aliceHeaders)).status, 402, 'but each only once')
})

test('a payment whose settlement fails can be retried with the same credential, then is spent', async () => {
  const r = route({ failSettleOnce: true })
  const w = wallet() // does not qualify, so it pays
  const headers = await w.native((await r.handle()).challenge)
  assert.equal((await r.handle(headers)).status, 402, 'settlement fails')
  assert.equal((await r.handle(headers)).status, 200, 'retry settles')
  w.qualify()
  assert.equal((await r.handle(headers)).status, 402, 'a settled credential cannot come back for free')
  assert.equal(r.counters.settles, 1)
})

test('an x402 credential valid for longer than the lifetime cap pays instead of getting free access', async () => {
  const r = route({ x402MaxTimeoutSeconds: 7200 })
  const w = wallet()
  w.qualify()
  const headers = await w.x402((await r.handle()).challenge)
  assert.equal((await r.handle(headers)).status, 200)
  assert.equal(r.counters.settles, 1, 'paid, not free')
  assert.equal((await r.handle(headers)).status, 402)
})

test('an x402 route with a long challenge expiry still gives short-lived credentials free access', async () => {
  const r = route({ expires: Expires.hours(2) })
  const w = wallet()
  w.qualify()
  const headers = await w.x402((await r.handle()).challenge)
  assert.deepEqual(await statuses(r.handle, headers, 2), [200, 402])
  assert.equal(r.counters.settleAttempts, 0)
})

test('a native route whose challenges outlive the lifetime cap pays instead', async () => {
  const r = route({ expires: Expires.hours(2) })
  const w = wallet()
  w.qualify()
  const headers = await w.native((await r.handle()).challenge)
  assert.deepEqual(await statuses(r.handle, headers, 2), [200, 402])
  assert.equal(r.counters.settles, 1, 'paid, not free')
})

test('mppx reports a free grant as payment.success, told apart by its receipt reference', async () => {
  const r = route()
  const references = []
  r.mppx.onPaymentSuccess(({ receipt }) => { references.push(receipt.reference) })

  const free = wallet()
  free.qualify()
  assert.equal((await r.handle(await free.native((await r.handle()).challenge))).status, 200)

  const paying = wallet()
  assert.equal((await r.handle(await paying.native((await r.handle()).challenge))).status, 200)

  assert.deepEqual(references, ['condition-gate:free:ATST-IT', '0xsettled'])
  assert.equal(r.counters.settles, 1)
})

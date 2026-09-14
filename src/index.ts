import type { Method, Receipt } from 'mppx'
import { Errors } from 'mppx'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ChainId = number | 'solana' | 'xrpl' | 'bitcoin'

/** ERC-20 / SPL / XRPL trust-line / native balance check */
export type TokenBalanceCondition = {
  type: 'token_balance'
  /** Token contract address. For XRPL native XRP or Bitcoin, use "native". */
  contractAddress: string
  chainId: ChainId
  /** Minimum balance in token units. Pass a decimal string (e.g. "1000") for
   *  full precision; keys minted today sign under the v2 scheme and reject a
   *  JSON number, so numbers are converted to strings before sending. Defaults to "1". */
  threshold?: number | string
  /** Token decimals. Auto-detected on most EVM chains if omitted. */
  decimals?: number
  /** XRPL currency code (e.g. "USD", "RLUSD") for trust-line tokens. */
  currency?: string
  /** Human-readable label (max 100 chars). */
  label?: string
}

/** ERC-721 / ERC-1155 / Solana cNFT / XRPL NFT ownership check */
export type NftOwnershipCondition = {
  type: 'nft_ownership'
  contractAddress: string
  chainId: ChainId
  /** XRPL NFToken taxon filter. XRPL only. */
  taxon?: number
  label?: string
}

/** EAS attestation check (Ethereum Attestation Service) */
export type EasAttestationCondition = {
  type: 'eas_attestation'
  /** EVM chain ID (typically Base 8453). */
  chainId: number
  /**
   * Pre-configured compliance template. Mutually exclusive with schemaId.
   * When provided, fills in schemaId / attester / indexer automatically.
   * See GET /v1/compliance/templates for the live list.
   */
  template?:
    | 'coinbase_verified_account'
    | 'coinbase_verified_country'
    | 'coinbase_one'
    | 'gitcoin_passport_score'
    | 'gitcoin_passport_active'
  /** EAS schema ID (bytes32 hex). Required if template is not provided. */
  schemaId?: string
  /** Expected attester address (case-insensitive). Optional. */
  attester?: string
  /**
   * EAS indexer contract address. Required for raw (non-template) conditions.
   * The verifier resolves the attestation UID via getAttestationUid(recipient, schema).
   */
  indexer?: string
  label?: string
}

/** Farcaster ID registration check (always on Optimism, chain 10) */
export type FarcasterIdCondition = {
  type: 'farcaster_id'
  label?: string
}

/** Self-scaling agent-spend check: met iff balance >= multiple * amount. RPC EVM chains only. */
export type RatioToAmountCondition = {
  type: 'ratio_to_amount'
  /** Token contract address, or "native" for the chain's native asset. */
  contractAddress: string
  /** EVM chain ID (ratio conditions are RPC EVM only). */
  chainId: number
  /** Collateralization multiple. Met iff balance >= multiple * amount. */
  multiple: number
  /** Per-request reference amount in token/display units (e.g. 100 for 100 USDC, not base units). */
  amount: number
  label?: string
}

/** Share-of-supply check: met iff balance / totalSupply() >= minFraction. RPC EVM + ERC-20 only. */
export type RatioToSupplyCondition = {
  type: 'ratio_to_supply'
  /** ERC-20 token contract address (does not accept "native"). */
  contractAddress: string
  /** EVM chain ID (ratio conditions are RPC EVM only). */
  chainId: number
  /** Required share of total supply, a fraction in (0, 1] (e.g. 0.005 for 0.5%). */
  minFraction: number
  label?: string
}

/** Any condition accepted by /v1/attest */
export type Condition =
  | TokenBalanceCondition
  | NftOwnershipCondition
  | EasAttestationCondition
  | FarcasterIdCondition
  | RatioToAmountCondition
  | RatioToSupplyCondition

/** Wallet family for a proven payer. */
export type WalletType = 'evm' | 'solana' | 'xrpl' | 'bitcoin'

/**
 * A payer the caller has cryptographically proven for this request.
 *
 * Accepts a `did:pkh:...` string, a bare `0x` EVM address, or an explicit
 * `{ address, type }` pair. Bare non-EVM addresses are rejected because their
 * wallet family cannot be inferred unambiguously — pass the object form.
 */
export type ProvenPayer =
  | string
  | { address: string; type: WalletType }
  | null
  | undefined

export type ConditionGateOptions = {
  /** InsumerAPI key. Falls back to INSUMER_API_KEY env var. */
  apiKey?: string
  /**
   * Resolves the payer that the payment method has PROVEN controls this
   * request. Required for free access — without it every request takes the
   * paid path.
   *
   * It receives only mppx's method-specific validation `details` (for example
   * a recovered payer address). It is deliberately NOT given the credential or
   * the declared `source`: mppx documents `source` as "an asserted identity,
   * not independent proof of control", and granting on it is the vulnerability
   * fixed in 3.0.0 (GHSA-jg6q-3qfh-r9f8).
   *
   * Return `null` when no payer has been proven. Returning an address you have
   * not proven reintroduces that vulnerability.
   *
   * @example
   * ```ts
   * provenPayer: (details) => (details as { payer?: string }).payer ?? null
   * ```
   */
  provenPayer?: (details: unknown) => ProvenPayer | Promise<ProvenPayer>
  /** One or more conditions to evaluate. Mix any of the six types. */
  conditions: Condition[]
  /** Whether the wallet must satisfy "any" (default) or "all" conditions. */
  matchMode?: 'any' | 'all'
  /** In-memory cache TTL in seconds. Defaults to 300 (5 minutes). */
  cacheTtlSeconds?: number
  /**
   * InsumerAPI base URL. Defaults to "https://api.insumermodel.com".
   * Override for self-hosted deployments or testing.
   */
  apiBaseUrl?: string
  /**
   * @deprecated No effect. The gate consumes the attestation internally and
   * returns only an mppx receipt, so a requested JWT never reached the caller.
   * Accepted for type compatibility; not sent to the API. Call POST /v1/attest
   * with `format: "jwt"` directly if you need the `jwt` and `pqJwt` tokens.
   */
  jwt?: boolean
  /**
   * Where the gate records credentials it has accepted, so each one gets
   * through at most once. Defaults to a bounded in-process store.
   *
   * Pass a shared store when the route runs on more than one instance, or a
   * credential used on one instance can be presented again on another. The
   * store must claim atomically and remove expired entries: `Store.redis`,
   * `Store.upstash` or `Store.cloudflare` from `mppx/server` built from a client
   * that exposes an atomic `update`, or any store with an atomic `tryClaim`.
   * mppx's `Store.memory()` never removes expired entries; use it only in tests.
   */
  replayStore?: ReplayStore
  /**
   * Longest remaining validity, in seconds, a credential may have and still be
   * given free access. Defaults to 600. The gate has to remember a credential
   * until it expires, and x402 clients choose their own expiry, so longer-lived
   * credentials take the paid path instead.
   */
  maxCredentialLifetimeSeconds?: number
}

/**
 * An atomic claim store. Structurally compatible with mppx's `AtomicStore`:
 * `tryClaim` is used when present, otherwise `update`. `get`, when present,
 * lets the gate refuse a repeat before spending an attestation on it, and
 * `delete` (or `update`) lets it release a credential whose payment failed.
 */
export type ReplayStore = {
  get?: (key: string) => unknown | Promise<unknown>
  delete?: (key: string) => void | Promise<void>
  tryClaim?: (key: string, expires: number) => boolean | Promise<boolean>
  update?: <result>(
    key: string,
    fn: (current: any) =>
      | { op: 'noop'; result: result }
      | { op: 'set'; value: any; result: result }
      | { op: 'delete'; result: result },
  ) => Promise<result>
}

export type InsumerAttestation = {
  ok: boolean
  data: {
    attestation: {
      id: string
      pass: boolean
      results: Array<{
        condition: number
        label?: string
        type: string
        chainId: number | string
        met: boolean
        evaluatedCondition: Record<string, unknown>
        conditionHash: string
        blockNumber?: string
        blockTimestamp?: string
        ledgerIndex?: number
        ledgerHash?: string
      }>
      passCount: number
      failCount: number
      attestedAt: string
      expiresAt: string
    }
    sig: string
    kid: string
    /** ML-DSA-65 post-quantum companion signature (since 2026-09-01, additive). */
    pqSig?: string
    /** Post-quantum key id, insumer-attest-pq1 (resolved in the JWKS as an RFC 9964 AKP entry). */
    pqKid?: string
    jwt?: string
    pqJwt?: string
  }
  meta: {
    version: string
    timestamp: string
    creditsRemaining: number
    creditsCharged: number
  }
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

type CacheEntry = {
  pass: boolean
  attestationId: string
  expiresAt: number
}

const cache = new Map<string, CacheEntry>()

function conditionSortKey(c: Condition): string {
  if (c.type === 'farcaster_id') return 'farcaster_id'
  if (c.type === 'eas_attestation') {
    return `eas:${c.chainId}:${(c.schemaId || c.template || '').toLowerCase()}`
  }
  return `${c.type}:${c.chainId}:${c.contractAddress.toLowerCase()}`
}

function cacheKey(address: string, conditions: Condition[]): string {
  const sorted = [...conditions].sort((a, b) => {
    const ka = conditionSortKey(a)
    const kb = conditionSortKey(b)
    return ka < kb ? -1 : ka > kb ? 1 : 0
  })
  return `${address.toLowerCase()}:${JSON.stringify(sorted)}`
}

/** Clear the in-memory ownership cache and the default replay store. Useful in tests. */
export function clearConditionGateCache(): void {
  cache.clear()
  defaultMarkers.clear()
  freeCountByOwner.clear()
  freeCount = 0
  paidCount = 0
  nextSweepAt = 0
}

// ---------------------------------------------------------------------------
// Single-use credentials
// ---------------------------------------------------------------------------

// mppx makes a credential single-use when it settles: the on-chain nonce is
// spent, or the method claims the hash or proof in its store. `validate` is
// non-mutating by design, so a credential that is granted free access and
// never settled would otherwise stay usable by anyone who holds a copy.

/** Kept this long past the credential's own expiry, to absorb clock skew. */
const REPLAY_SKEW_MS = 60 * 1000
const DEFAULT_MAX_CREDENTIAL_LIFETIME_SECONDS = 600
/** Default store: live free grants across the process, and per wallet. */
const DEFAULT_STORE_MAX_FREE = 100_000
const DEFAULT_STORE_MAX_FREE_PER_WALLET = 5_000
/** Default store: payments it remembers. Past this it stops recording payments. */
const DEFAULT_STORE_MAX_PAID = 100_000
const DEFAULT_STORE_SWEEP_MS = 60_000

type RecordKind = 'free' | 'paid'
type DefaultMarker = { expires: number; owner: string; kind: RecordKind }

const defaultMarkers = new Map<string, DefaultMarker>()
const freeCountByOwner = new Map<string, number>()
let freeCount = 0
let paidCount = 0
let nextSweepAt = 0

function forgetDefault(key: string): void {
  const marker = defaultMarkers.get(key)
  if (!marker) return
  defaultMarkers.delete(key)
  if (marker.kind === 'paid') {
    paidCount--
    return
  }
  freeCount--
  const remaining = (freeCountByOwner.get(marker.owner) ?? 1) - 1
  if (remaining <= 0) freeCountByOwner.delete(marker.owner)
  else freeCountByOwner.set(marker.owner, remaining)
}

/** What the gate needs from a store. The default store and a caller's store both sit behind it. */
type Recorder = {
  isTaken(key: string): Promise<boolean>
  /** true when claimed, false when already taken; throws when it cannot record. */
  claim(key: string, expires: number, owner: string, kind: RecordKind): Promise<boolean>
  release(key: string): Promise<void>
}

const defaultRecorder: Recorder = {
  async isTaken(key) {
    const marker = defaultMarkers.get(key)
    return marker !== undefined && marker.expires > Date.now()
  },
  async claim(key, expires, owner, kind) {
    const now = Date.now()
    if (now >= nextSweepAt) {
      for (const [k, marker] of defaultMarkers) if (marker.expires <= now) forgetDefault(k)
      nextSweepAt = now + DEFAULT_STORE_SWEEP_MS
    }
    const current = defaultMarkers.get(key)
    if (current !== undefined) {
      if (current.expires > now) return false
      forgetDefault(key)
    }
    if (kind === 'free') {
      const held = freeCountByOwner.get(owner) ?? 0
      if (freeCount >= DEFAULT_STORE_MAX_FREE || held >= DEFAULT_STORE_MAX_FREE_PER_WALLET) {
        throw new Error('mppx-condition-gate: default replay store has no room for this wallet')
      }
      freeCount++
      freeCountByOwner.set(owner, held + 1)
    } else {
      if (paidCount >= DEFAULT_STORE_MAX_PAID) {
        throw new Error('mppx-condition-gate: default replay store is full')
      }
      paidCount++
    }
    defaultMarkers.set(key, { expires, owner, kind })
    return true
  },
  async release(key) {
    forgetDefault(key)
  },
}

function isReplayMarker(value: unknown): value is { expires: number; type: 'mppx:replay' } {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { expires?: unknown }).expires === 'number' &&
    (value as { type?: unknown }).type === 'mppx:replay'
  )
}

async function tryClaim(store: ReplayStore, key: string, expires: number): Promise<boolean> {
  if (typeof store.tryClaim === 'function') return store.tryClaim(key, expires)
  // Same marker as mppx's Store.tryClaim. A live marker, or any other stored
  // value, counts as taken; an empty slot or an expired marker does not.
  return store.update!(key, (current) => {
    const empty = current === null || current === undefined || current === false
    const taken = !empty && (!isReplayMarker(current) || current.expires > Date.now())
    return taken
      ? { op: 'noop', result: false }
      : { op: 'set', value: { expires, type: 'mppx:replay' }, result: true }
  })
}

function storeRecorder(store: ReplayStore): Recorder {
  return {
    async isTaken(key) {
      // Advisory only: the atomic claim decides. Anything but a live marker reads as free.
      if (typeof store.get !== 'function') return false
      const current = await store.get(key)
      return isReplayMarker(current) && current.expires > Date.now()
    },
    async claim(key, expires) {
      return tryClaim(store, key, expires)
    },
    async release(key) {
      if (typeof store.delete === 'function') {
        await store.delete(key)
        return
      }
      if (typeof store.update === 'function') {
        await store.update(key, (current) =>
          isReplayMarker(current)
            ? { op: 'delete', result: undefined }
            : { op: 'noop', result: undefined },
        )
      }
    },
  }
}

function lowerHex(value: unknown): string | null {
  return typeof value === 'string' && /^0x[0-9a-fA-F]+$/.test(value) ? value.toLowerCase() : null
}

/**
 * One key that identifies the credential, or null when the gate cannot
 * identify it safely, in which case it gets no free access.
 *
 * - EIP-3009 authorization (mppx EVM charge, native and x402): signer + nonce.
 *   Neither changes when the signature is re-encoded or the challenge is
 *   rebuilt, and two users never share one.
 * - Tempo proof: challenge id + proven payer. The proof signs the challenge
 *   id, so it cannot be moved to another challenge.
 *
 * Other credential types are payments in their own right (a Tempo hash is a
 * transfer already on chain, a Tempo transaction is one waiting to be sent),
 * so they take the paid path, where the method's own replay protection applies.
 */
function credentialKey(methodName: string, credential: any, payerAddress: string): string | null {
  const payload = credential?.payload
  if (payload === null || typeof payload !== 'object') return null
  let id: string | null = null
  if (payload.type === 'authorization') {
    const from = lowerHex(payload.from)
    const nonce = lowerHex(payload.nonce)
    if (from && nonce) id = `authorization:${from}:${nonce}`
  } else if (payload.type === 'proof') {
    const challengeId = credential?.challenge?.id
    if (typeof challengeId === 'string' && challengeId.length > 0) {
      id = `proof:${challengeId}:${payerAddress.toLowerCase()}`
    }
  }
  return id === null ? null : `mppx-condition-gate:${methodName}:${id}`
}

/** The latest moment the credential could still be accepted, or null if unknown. */
function credentialExpiry(credential: any): number | null {
  const payload = credential?.payload
  if (payload?.type === 'authorization') {
    // An authorization is bounded by its own validBefore. For x402 the
    // challenge is rebuilt on every request, so its expiry says nothing about
    // the credential; a native credential's validBefore is its challenge's expiry.
    const validBefore = Number(payload.validBefore)
    return Number.isFinite(validBefore) && validBefore > 0 ? validBefore * 1000 : null
  }
  const challengeExpires = Date.parse(credential?.challenge?.expires)
  return Number.isFinite(challengeExpires) ? challengeExpires : null
}

// ---------------------------------------------------------------------------
// DID parsing
// ---------------------------------------------------------------------------

/**
 * Extracts an EVM address from a `did:pkh:eip155:{chainId}:{address}` string.
 * Returns null for non-EVM or unparseable DIDs.
 */
export function parseDid(source: string): `0x${string}` | null {
  const parts = source.split(':')
  if (parts.length !== 5) return null
  if (parts[0] !== 'did' || parts[1] !== 'pkh' || parts[2] !== 'eip155') return null
  const address = parts[4]
  if (!address || !address.startsWith('0x')) return null
  return address as `0x${string}`
}

/** Extracts a Solana address from a `did:pkh:solana:{chainId}:{address}` string. */
export function parseSolanaDid(source: string): string | null {
  const parts = source.split(':')
  if (parts.length !== 5) return null
  if (parts[0] !== 'did' || parts[1] !== 'pkh' || parts[2] !== 'solana') return null
  return parts[4] || null
}

/** Extracts an XRPL address from a `did:pkh:xrpl:{chainId}:{address}` string. */
export function parseXrplDid(source: string): string | null {
  const parts = source.split(':')
  if (parts.length !== 5) return null
  if (parts[0] !== 'did' || parts[1] !== 'pkh' || parts[2] !== 'xrpl') return null
  const address = parts[4]
  if (!address || !address.startsWith('r')) return null
  return address
}

/** Extracts a Bitcoin address from a `did:pkh:bip122:{chainId}:{address}` string. */
export function parseBitcoinDid(source: string): string | null {
  const parts = source.split(':')
  if (parts.length !== 5) return null
  if (parts[0] !== 'did' || parts[1] !== 'pkh' || parts[2] !== 'bip122') return null
  return parts[4] || null
}

// ---------------------------------------------------------------------------
// InsumerAPI call
// ---------------------------------------------------------------------------

function buildBodyConditions(conditions: Condition[]): Array<Record<string, unknown>> {
  return conditions.map((c) => {
    if (c.type === 'farcaster_id') {
      const cond: Record<string, unknown> = { type: c.type }
      if (c.label) cond.label = c.label
      return cond
    }
    if (c.type === 'eas_attestation') {
      const cond: Record<string, unknown> = {
        type: c.type,
        chainId: c.chainId,
      }
      if (c.template) cond.template = c.template
      if (c.schemaId) cond.schemaId = c.schemaId
      if (c.attester) cond.attester = c.attester
      if (c.indexer) cond.indexer = c.indexer
      if (c.label) cond.label = c.label
      return cond
    }
    if (c.type === 'ratio_to_amount') {
      const cond: Record<string, unknown> = {
        type: c.type,
        contractAddress: c.contractAddress,
        chainId: c.chainId,
        multiple: c.multiple,
        amount: c.amount,
      }
      if (c.label) cond.label = c.label
      return cond
    }
    if (c.type === 'ratio_to_supply') {
      const cond: Record<string, unknown> = {
        type: c.type,
        contractAddress: c.contractAddress,
        chainId: c.chainId,
        minFraction: c.minFraction,
      }
      if (c.label) cond.label = c.label
      return cond
    }
    // token_balance or nft_ownership
    const cond: Record<string, unknown> = {
      type: c.type,
      contractAddress: c.contractAddress,
      chainId: c.chainId,
    }
    if (c.type === 'token_balance') {
      const threshold = c.threshold ?? '1'
      cond.threshold = typeof threshold === 'string' ? threshold : String(threshold)
      if (c.decimals !== undefined) cond.decimals = c.decimals
      if (c.currency) cond.currency = c.currency
    }
    if (c.type === 'nft_ownership' && c.taxon !== undefined) {
      cond.taxon = c.taxon
    }
    if (c.label) cond.label = c.label
    return cond
  })
}

async function callAttest(
  wallet: string,
  walletType: 'evm' | 'solana' | 'xrpl' | 'bitcoin',
  conditions: Condition[],
  options: Pick<ConditionGateOptions, 'apiKey' | 'apiBaseUrl'>,
): Promise<InsumerAttestation> {
  const apiKey = options.apiKey || process.env.INSUMER_API_KEY
  if (!apiKey) {
    throw new Error(
      'mppx-condition-gate: Missing API key. Pass apiKey in options or set INSUMER_API_KEY env var. ' +
      'Get a free key: POST https://api.insumermodel.com/v1/keys/create',
    )
  }

  const baseUrl = options.apiBaseUrl || 'https://api.insumermodel.com'

  const body: Record<string, unknown> = {
    conditions: buildBodyConditions(conditions),
  }

  if (walletType === 'solana') body.solanaWallet = wallet
  else if (walletType === 'xrpl') body.xrplWallet = wallet
  else if (walletType === 'bitcoin') body.bitcoinWallet = wallet
  else body.wallet = wallet

  const response = await fetch(`${baseUrl}/v1/attest`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
    },
    body: JSON.stringify(body),
  })

  const data = await response.json() as InsumerAttestation
  if (!response.ok || !data.ok) {
    const msg = (data as any)?.error?.message || `HTTP ${response.status}`
    throw new Error(`mppx-condition-gate: Attestation failed: ${msg}`)
  }
  return data
}

// ---------------------------------------------------------------------------
// conditionGate adapter
// ---------------------------------------------------------------------------

/**
 * Normalizes a caller-supplied proven payer into an address + wallet family.
 *
 * Fail-closed: anything it cannot resolve unambiguously returns null, which
 * sends the request to the paid path.
 */
export function normalizeProvenPayer(
  payer: ProvenPayer,
): { address: string; type: WalletType } | null {
  if (!payer) return null

  if (typeof payer === 'object') {
    const { address, type } = payer
    if (!address || !type) return null
    return { address, type }
  }

  if (typeof payer !== 'string') return null

  const evm = parseDid(payer)
  if (evm) return { address: evm, type: 'evm' }
  const sol = parseSolanaDid(payer)
  if (sol) return { address: sol, type: 'solana' }
  const xrpl = parseXrplDid(payer)
  if (xrpl) return { address: xrpl, type: 'xrpl' }
  const btc = parseBitcoinDid(payer)
  if (btc) return { address: btc, type: 'bitcoin' }

  // Bare EVM address is unambiguous; anything else needs the object form.
  if (payer.startsWith('0x')) return { address: payer, type: 'evm' }
  return null
}

/**
 * Wraps an mppx Method.Server with condition-based access using signed attestations.
 *
 * Free access requires a PROVEN payer. The gate calls the method's non-mutating
 * `validate` hook, hands the resulting method-specific `details` to your
 * `provenPayer` resolver, and only then evaluates conditions. It never reads
 * `credential.source` — mppx documents that field as an asserted identity
 * rather than proof of control.
 *
 * The gate falls through to the paid path whenever free access cannot be
 * justified: no `provenPayer` resolver, no `validate` hook on the method
 * (legacy `verify`-only methods included), a resolver returning null, a
 * credential that fails validation, conditions not met, or an attestation
 * error. There is no path from an unproven wallet to a free receipt.
 *
 * Each credential gets free access at most once. The gate records a
 * credential when it grants free access, and records an authorization just
 * before the paid path settles it; a recorded credential is refused with a
 * verification error rather than passed on to payment. A payment that fails is
 * released, so it can be retried. See the README for the limits of this. Free access is given only to credentials the gate can identify
 * (EIP-3009 authorizations and Tempo proofs) whose remaining validity is within
 * `maxCredentialLifetimeSeconds`. The default store is bounded and shared by
 * every gated route in the process; pass a shared `replayStore` for production
 * traffic or when the route runs on more than one instance.
 *
 * Conditions are evaluated across the 35 chains this adapter reaches (32 EVM +
 * Solana + XRPL + Bitcoin; the engine itself covers 38). Six condition types
 * are typed here: token_balance, nft_ownership, eas_attestation, farcaster_id,
 * ratio_to_amount, and ratio_to_supply. InsumerAPI also offers evm_view_call,
 * erc8004_agent, and erc7710_delegation; those are not typed or normalized
 * here, so call /v1/attest directly if you need them.
 *
 * The attestation is ECDSA P-256 signed and verifiable offline via the public
 * JWKS at https://insumermodel.com/.well-known/jwks.json.
 *
 * @example
 * ```ts
 * import { conditionGate } from '@insumermodel/mppx-condition-gate'
 *
 * const gated = conditionGate(evmCharge, {
 *   // Return only a payer this method has proven for THIS request.
 *   // mppx's EVM charge reports the recovered signer as `payer`.
 *   provenPayer: (details) => (details as { payer?: string }).payer ?? null,
 *   conditions: [
 *     { type: 'eas_attestation', template: 'coinbase_verified_account', chainId: 8453 },
 *     { type: 'farcaster_id' },
 *   ],
 *   matchMode: 'any',
 * })
 *
 * const mppx = Mppx.create({ methods: [gated] })
 * ```
 */
export function conditionGate(
  server: Method.AnyServer,
  options: ConditionGateOptions,
): Method.AnyServer {
  const { conditions, matchMode = 'any', cacheTtlSeconds = 300, provenPayer } = options
  const lifetimeSeconds = options.maxCredentialLifetimeSeconds ?? DEFAULT_MAX_CREDENTIAL_LIFETIME_SECONDS
  if (typeof lifetimeSeconds !== 'number' || !Number.isFinite(lifetimeSeconds) || lifetimeSeconds < 0) {
    throw new Error('mppx-condition-gate: maxCredentialLifetimeSeconds must be a finite number of seconds, 0 or more.')
  }
  const maxLifetimeMs = lifetimeSeconds * 1000

  const { replayStore } = options
  if (
    replayStore !== undefined &&
    typeof replayStore.tryClaim !== 'function' &&
    typeof replayStore.update !== 'function'
  ) {
    throw new Error('mppx-condition-gate: replayStore must provide an atomic tryClaim or update (an mppx AtomicStore).')
  }
  const recorder = replayStore ? storeRecorder(replayStore) : defaultRecorder

  const anyServer = server as unknown as {
    verify: (params: any) => Promise<any>
    broadcast?: (params: any) => Promise<any>
    validate?: (params: any) => Promise<any>
  }

  const originalVerify = anyServer.verify
  const originalBroadcast = anyServer.broadcast
  const originalValidate = anyServer.validate

  // Free access is only reachable when BOTH exist: a resolver to supply the
  // proven payer, and a non-mutating validate hook to derive it from. A method
  // without `validate` (legacy verify-only, or broadcast-without-validate) has
  // no safe pre-check, so it is never gated.
  const canGate =
    typeof provenPayer === 'function' && typeof originalValidate === 'function'

  const refuse = () =>
    new Errors.VerificationFailedError({ reason: 'this credential has already been presented' })

  /** Attestation result for a payer, from the cache or a fresh call. Throws on API error. */
  async function evaluate(payer: { address: string; type: WalletType }) {
    const key = cacheKey(payer.address, conditions)
    const cached = cache.get(key)
    if (cached && cached.expiresAt > Date.now()) return cached

    const result = await callAttest(payer.address, payer.type, conditions, options)
    const attestation = result.data.attestation
    const pass =
      matchMode === 'all'
        ? attestation.pass
        : attestation.results.some((r) => r.met)
    const entry = {
      pass,
      attestationId: attestation.id,
      expiresAt: Date.now() + cacheTtlSeconds * 1000,
    }
    cache.set(key, entry)
    return entry
  }

  type Attempt =
    | { free: true; receipt: any }
    | { free: false; record?: { key: string; expires: number; owner: string; payment: boolean } }

  /** Decides between a free receipt and the paid path. Throws to refuse a repeat. */
  async function tryFree(params: any): Promise<Attempt> {
    if (!canGate) return { free: false }

    let details: unknown
    try {
      const validation = await originalValidate!(params)
      details = (validation as { details?: unknown } | undefined)?.details
    } catch {
      // Credential is not currently acceptable → let the payment method decide.
      return { free: false }
    }

    let resolved: ProvenPayer
    try {
      resolved = await provenPayer!(details)
    } catch {
      return { free: false }
    }

    const payer = normalizeProvenPayer(resolved)
    if (!payer) return { free: false }

    const credential = params?.credential
    const key = credentialKey(server.name, credential, payer.address)
    const expiry = credentialExpiry(credential)
    if (key === null || expiry === null) return { free: false }

    const record = {
      key,
      owner: payer.address.toLowerCase(),
      expires: Math.min(expiry + REPLAY_SKEW_MS, Number.MAX_SAFE_INTEGER),
      // Only an authorization moves value; a Tempo proof is accepted on zero-amount routes.
      payment: credential?.payload?.type === 'authorization',
    }

    // A recorded credential is refused before any attestation is spent on it.
    let taken: boolean
    try {
      taken = await recorder.isTaken(key)
    } catch {
      return { free: false, record }
    }
    if (taken) {
      // A repeated Tempo proof moves no value, so the method decides; a payment is refused.
      if (!record.payment) return { free: false }
      throw refuse()
    }

    if (expiry - Date.now() > maxLifetimeMs) return { free: false, record }

    let evaluation: CacheEntry
    try {
      evaluation = await evaluate(payer)
    } catch {
      // Attestation error → paid path.
      return { free: false, record }
    }
    if (!evaluation.pass) return { free: false, record }

    let claimed: boolean
    try {
      claimed = await recorder.claim(key, record.expires, record.owner, 'free')
    } catch {
      // The store cannot record the credential, so it gets no free access.
      return { free: false, record }
    }
    if (!claimed) {
      if (!record.payment) return { free: false }
      throw refuse()
    }

    return {
      free: true,
      receipt: {
        method: server.name,
        reference: `condition-gate:free:${evaluation.attestationId}`,
        status: 'success' as const,
        timestamp: new Date().toISOString(),
      },
    }
  }

  /** Runs the gate, then the original method on the paid path. */
  async function gated(original: (params: any) => Promise<any>, params: any) {
    const attempt = await tryFree(params)
    if (attempt.free) return attempt.receipt

    const record = attempt.record
    let claimed = false
    // Only a payment is recorded on this path. A Tempo proof moves no value, so
    // the method's own rules decide whether it may be presented again.
    if (record && record.payment) {
      // Claimed before settlement, so a copy presented while this payment is
      // in flight is refused too. Kept until the credential itself expires.
      let result: boolean | null
      try {
        result = await recorder.claim(record.key, record.expires, record.owner, 'paid')
      } catch {
        // Cannot record: pay as bare mppx would; the method's own replay protection applies.
        result = null
      }
      if (result === false) throw refuse()
      claimed = result === true
    }

    try {
      return await original(params)
    } catch (error) {
      // A payment that fails is released, so the holder can retry with the same credential.
      if (claimed) {
        try {
          await recorder.release(record!.key)
        } catch {
          // Stays recorded until it expires.
        }
      }
      throw error
    }
  }

  const wrapped = { ...server } as unknown as Record<string, unknown>

  if (typeof originalBroadcast === 'function') {
    wrapped.broadcast = async (params: any) => gated(originalBroadcast, params)
  }

  wrapped.verify = async (params: any) => gated(originalVerify, params)

  return wrapped as unknown as Method.AnyServer
}

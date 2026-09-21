import type { Method, Receipt } from 'mppx'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type TokenCondition = {
  /** Token or NFT contract address. For XRPL native XRP, use "native". */
  contractAddress: string
  /**
   * Chain identifier.
   * EVM chain ID (number), "solana", "xrpl", or "bitcoin".
   */
  chainId: number | 'solana' | 'xrpl' | 'bitcoin'
  /** "token_balance" or "nft_ownership". */
  type: 'token_balance' | 'nft_ownership'
  /** Minimum balance for token_balance conditions. Defaults to 1. */
  threshold?: number
  /** Optional cross-check: the token's own decimals are always read from the chain, and a differing value is rejected. Best left out. */
  decimals?: number
  /** Human-readable label (max 100 chars). */
  label?: string
  /** XRPL currency code (e.g. "USD", "RLUSD"). Only for XRPL trust-line tokens. */
  currency?: string
  /** XRPL NFT taxon filter. Only for XRPL nft_ownership. */
  taxon?: number
}

export type TokenGateOptions = {
  /** InsumerAPI key. Falls back to INSUMER_API_KEY env var. */
  apiKey?: string
  /** One or more token/NFT conditions to check. */
  conditions: TokenCondition[]
  /** Whether the payer must satisfy "any" (default) or "all" conditions. */
  matchMode?: 'any' | 'all'
  /** In-memory cache TTL in seconds. Defaults to 300 (5 minutes). */
  cacheTtlSeconds?: number
  /**
   * InsumerAPI base URL. Defaults to "https://api.insumermodel.com".
   * Override for testing or self-hosted deployments.
   */
  apiBaseUrl?: string
  /** Request JWT format alongside the raw attestation. Defaults to false. */
  jwt?: boolean
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
    jwt?: string
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

function cacheKey(address: string, conditions: TokenCondition[]): string {
  const sorted = [...conditions].sort((a, b) => {
    const ca = `${a.chainId}:${a.contractAddress}`.toLowerCase()
    const cb = `${b.chainId}:${b.contractAddress}`.toLowerCase()
    return ca < cb ? -1 : ca > cb ? 1 : 0
  })
  return `${address.toLowerCase()}:${JSON.stringify(sorted)}`
}

/** Clear the in-memory ownership cache. Useful in tests. */
export function clearTokenGateCache(): void {
  cache.clear()
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

/**
 * Extracts a Solana address from a `did:pkh:solana:{chainId}:{address}` string.
 */
export function parseSolanaDid(source: string): string | null {
  const parts = source.split(':')
  if (parts.length !== 5) return null
  if (parts[0] !== 'did' || parts[1] !== 'pkh' || parts[2] !== 'solana') return null
  return parts[4] || null
}

/**
 * Extracts an XRPL address from a `did:pkh:xrpl:{chainId}:{address}` string.
 */
export function parsXrplDid(source: string): string | null {
  const parts = source.split(':')
  if (parts.length !== 5) return null
  if (parts[0] !== 'did' || parts[1] !== 'pkh' || parts[2] !== 'xrpl') return null
  const address = parts[4]
  if (!address || !address.startsWith('r')) return null
  return address
}

/**
 * Extracts a Bitcoin address from a `did:pkh:bip122:{chainId}:{address}` string.
 */
export function parseBitcoinDid(source: string): string | null {
  const parts = source.split(':')
  if (parts.length !== 5) return null
  if (parts[0] !== 'did' || parts[1] !== 'pkh' || parts[2] !== 'bip122') return null
  return parts[4] || null
}

// ---------------------------------------------------------------------------
// InsumerAPI call
// ---------------------------------------------------------------------------

async function callAttest(
  wallet: string,
  walletType: 'evm' | 'solana' | 'xrpl' | 'bitcoin',
  conditions: TokenCondition[],
  options: Pick<TokenGateOptions, 'apiKey' | 'apiBaseUrl' | 'jwt'>,
): Promise<InsumerAttestation> {
  const apiKey = options.apiKey || process.env.INSUMER_API_KEY
  if (!apiKey) {
    throw new Error(
      'mppx-token-gate: Missing API key. Pass apiKey in options or set INSUMER_API_KEY env var. ' +
      'Get a free key: POST https://api.insumermodel.com/v1/keys/create',
    )
  }

  const baseUrl = options.apiBaseUrl || 'https://api.insumermodel.com'

  const body: Record<string, unknown> = {
    conditions: conditions.map((c) => {
      const cond: Record<string, unknown> = {
        type: c.type,
        contractAddress: c.contractAddress,
        chainId: c.chainId,
      }
      if (c.type === 'token_balance') {
        // Current API keys require the threshold as a decimal string.
        cond.threshold = String(c.threshold ?? 1)
      }
      if (c.decimals !== undefined) cond.decimals = c.decimals
      if (c.label) cond.label = c.label
      if (c.currency) cond.currency = c.currency
      if (c.taxon !== undefined) cond.taxon = c.taxon
      return cond
    }),
  }

  if (walletType === 'solana') body.solanaWallet = wallet
  else if (walletType === 'xrpl') body.xrplWallet = wallet
  else if (walletType === 'bitcoin') body.bitcoinWallet = wallet
  else body.wallet = wallet

  if (options.jwt) body.format = 'jwt'

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
    throw new Error(`mppx-token-gate: Attestation failed — ${msg}`)
  }
  return data
}

// ---------------------------------------------------------------------------
// tokenGate wrapper
// ---------------------------------------------------------------------------

/**
 * Wraps an mppx Method.Server. **This gate no longer grants free access.**
 *
 * Every request is delegated to the wrapped payment method.
 *
 * Versions 1.0.0 through 1.0.3 granted free access based on the payer address
 * in `credential.source` — a client-supplied value that mppx documents as "an
 * asserted identity, not independent proof of control". Nothing established
 * that the caller controlled the wallet it named, and because qualifying
 * wallets are public chain state, anyone could name one and skip payment
 * (GHSA-jg6q-3qfh-r9f8).
 *
 * This package has no way to obtain a payer that the payment method has
 * actually proven, so there is no safe way for it to grant free access. The
 * grant has been removed rather than patched: the feature only ever worked
 * because it was insecure.
 *
 * **This package is deprecated.** For condition-based free access with a proven
 * payer, use `@insumermodel/mppx-condition-gate` v3 or later, which requires a
 * `provenPayer` resolver.
 *
 * The signature is unchanged so existing code keeps compiling; the behaviour is
 * that all traffic takes the paid path.
 *
 * @deprecated Use `@insumermodel/mppx-condition-gate` v3+.
 */
export function tokenGate(
  server: Method.AnyServer,
  options: TokenGateOptions,
): Method.AnyServer {
  void options
  // No free-access path exists. See the note above: this package cannot obtain
  // a proven payer, so it cannot safely grant anything.
  return server
}

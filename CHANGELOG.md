# Changelog

## 3.2.3 (2026-11-09)

- Each route now judges a cached attestation by its own `cacheTtlSeconds`. The cache is shared by every gated route in the process, and an entry used to carry the expiry of the route that wrote it, so a route with a short TTL (or `0`, meaning check every time) could still grant free access on a pass another route had cached for longer. Entries now record when the attestation was made, and a route uses one only while it is younger than that route's own TTL; a TTL of `0` never reads the cache. Found in an internal security review after GHSA-jxpm-8jpg-38xc; it affects only setups with two or more gated routes on the same conditions and different `cacheTtlSeconds`.

## 3.2.2 (2026-11-09)

- Fixes the attestation cache key ([GHSA-jxpm-8jpg-38xc](https://github.com/insumerapi/mppx-condition-gate/security/advisories/GHSA-jxpm-8jpg-38xc), low). The cache is shared by every gated route in the process, and its key held only the wallet and the conditions, while the cached result already had the route's `matchMode` applied. A wallet that passed an `'any'` route could then get free access on an `'all'` route with the same conditions until the entry expired (`cacheTtlSeconds`, default 300). The key now also holds `matchMode`, the wallet type and `apiBaseUrl`, so routes that differ in any of them never share an entry. Only setups with two or more gated routes on the same conditions and different `matchMode` were affected. Thanks to @zohuyhieuzo03 for the report.
- The cache keeps Solana, XRPL and Bitcoin addresses exactly as given. Only EVM addresses are lowercased, since only they are case-insensitive.

## 3.2.1 (2026-10-21)

- README: on-chain key purchases and top-ups are USDC only (Ethereum, Base, Polygon, Arbitrum, Optimism, BNB Chain, Avalanche, Solana), and the paying wallet signs a short text naming the payment (`senderSignature`). USDT, Bitcoin and Tron are no longer accepted for purchases.
- Ships the documentation changes made since 3.2.0: the post-quantum signature named as such (signed twice: ES256 and ML-DSA-65) in the README and a type comment, version and license badges, plain punctuation. No code changes.

## 3.2.0 (2026-10-07)

- Adds the `account_code` condition type (`AccountCodeCondition`), the seventh typed here: `{ type: 'account_code', chainId: <EVM id>, expect: 'none' | 'eip7702' | 'contract' }` checks the code state of the wallet address itself at the anchored block (a plain key account, the EIP-7702 delegation designator, or any other code). With `expect: 'eip7702'` an optional `delegate` address is met only when the designator points at it. The result is the boolean `met`; the code and the delegation target are never returned. EVM chains only. The gate sends `chainId`, `expect`, `delegate` and `label` for this type, and keys its cache on them. The published type declarations follow.

## 3.1.4 (2026-10-05)

- Corrects the doc comment on `NftOwnershipCondition`: on EVM chains `nft_ownership` reads ERC-721 style contracts, so ERC-1155 is no longer listed. The published type declarations follow.
- Notes on `currency` that XRPL currency codes are case-sensitive and are sent exactly as given. No code changes.

## 3.1.3 (2026-10-04)

- Enhances the README: mppx reports a free grant through its `payment.success` event, so a server that counts payments from that event should check for the `condition-gate:free:` receipt reference. Adds an end-to-end test for it.
- Runs the tests on mppx 0.13.1 and viem 2.57.2 (dev dependencies). No code changes; the `mppx` peer range is unchanged.

## 3.1.2 (2026-10-02)

- Package metadata and README links point to the repository's current home, github.com/insumerapi/mppx-condition-gate. Adds the MIT license file to the package. No code changes.

## 3.1.1 (2026-09-20)

- Sends ratio quantities as decimal strings, as current API keys require: `multiple` and `amount` on `ratio_to_amount` and `minFraction` on `ratio_to_supply` now accept `string | number`, and a number is converted before sending.
- Adds the exported `toDecimalString` helper, used for `threshold` as well. It writes numbers without exponent notation (`1e-7` becomes `"0.0000001"`), and a quantity that is NaN or Infinity is reported when the gate is created.
- Updates the README examples to pass ratio quantities as strings (`'10'`, `'250'`, `'0.005'`).
- Clarifies that `decimals` is an optional cross-check: leave it out and the token's own decimals are read from the chain. A value that differs from the token's own is rejected with a 400. The token balance example no longer sends it.
- Aligns chain counts with the engine: 37 chains, 31 EVM; this adapter reaches 34. NFT ownership on 33. EAS conditions evaluate on Ethereum, Optimism, Polygon, Base and Arbitrum.
- Clarifies that `"native"` is for `token_balance` and `ratio_to_amount` only; `nft_ownership` needs the NFT contract address.

## 3.1.0 (2026-09-14)

- Enforces single-use free access. A free grant never settles, so it never spends the credential the way a payment does; the gate now records a credential when it grants free access, and records an authorization just before the paid path settles it, and refuses a recorded credential with a verification error instead of passing it on to payment. A payment that fails is released, so it can be retried. The README lists the limits of this guarantee.
- Identifies credentials by signer and nonce for EIP-3009 authorizations (mppx EVM charge, native and x402) and by challenge and payer for Tempo proofs. Other credential types take the paid path, where the method's own replay protection applies.
- Adds the `replayStore` option for an atomic shared store. The default store is in-process, shared by every gated route, and bounded: 100,000 live free grants with at most 5,000 per wallet, and up to 100,000 payment records. It is meant for development and low-stakes routes.
- Adds the `maxCredentialLifetimeSeconds` option (default 600). A credential valid for longer takes the paid path; an authorization's lifetime is its own `validBefore`.
- Makes `mppx` a required peer dependency at `>=0.8.14`, the first release with the `validate` hook, since the gate now uses its error types at runtime. Free access on the EVM charge needs mppx 0.9.3 or later, where that method gained `validate`.
- Enhances the documentation: the usage example uses the EVM charge, and new sections cover which credentials can get free access, the limits of single use, the default store, and running across instances.
- Adds end-to-end tests through the real mppx 0.9.3 server handler and client; mppx and viem are pinned as dev dependencies.

## 3.0.2 (2026-09-02)

- Enhances the README so it references only endpoints the gate uses: the free-receipt reference carries the `id` of the attestation returned by `POST /v1/attest`, and the gate keeps only `id` and `pass` in its cache.
- Adds the post-quantum companion fields (`pqSig`, `pqKid`, `pqJwt`) to the `InsumerAttestation` type and notes that every attest response carries them since 2026-09-01.
- Deprecates the `jwt` option: it is still accepted for type compatibility but no longer sent, since the gate returns only an mppx receipt and never surfaced the token. Callers who need `jwt`/`pqJwt` call `POST /v1/attest` with `format: "jwt"` directly.

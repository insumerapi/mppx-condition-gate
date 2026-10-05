# Changelog

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

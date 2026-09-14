# Changelog

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

# @insumermodel/mppx-token-gate

> **Deprecated. Use [`@insumermodel/mppx-condition-gate`](https://www.npmjs.com/package/@insumermodel/mppx-condition-gate) v3 or later.**

**As of 1.0.4 this package no longer grants free access.** Every request is delegated to the wrapped payment method.

## Why

Versions 1.0.0 through 1.0.3 granted free access based on the payer address in `credential.source`. That value is supplied by the caller, and mppx documents it as *"an asserted identity, not independent proof of control"*. Nothing in the gate established that the caller controlled the wallet it named — and because qualifying wallets are public chain state, there was nothing to guess. Anyone could name a qualifying wallet and skip payment.

Tracked as [GHSA-jg6q-3qfh-r9f8](https://github.com/insumerapi/mppx-condition-gate/security/advisories/GHSA-jg6q-3qfh-r9f8).

## Why the grant was removed rather than repaired

Granting free access safely requires a payer the payment method has actually **proven**. This package has no way to obtain one — it only ever saw the asserted `source`. So there is no safe version of the feature here. The free-access path only worked because it was insecure, and it has been removed.

`tokenGate()` keeps its signature, so existing code continues to compile. The behaviour is that all traffic takes the paid path.

## Upgrading

`@insumermodel/mppx-condition-gate` v3+ does this correctly. It requires a `provenPayer` resolver that receives only mppx's method-specific validation `details` — never the credential, never `source` — and falls through to payment wherever a proven payer is not available.

```diff
- import { tokenGate } from '@insumermodel/mppx-token-gate'
+ import { conditionGate } from '@insumermodel/mppx-condition-gate'

- const gated = tokenGate(server, { conditions: [...] })
+ const gated = conditionGate(server, {
+   provenPayer: (details) => (details as { payer?: string }).payer ?? null,
+   conditions: [...],
+ })
```

Receipt references change from `token-gate:free:` to `condition-gate:free:`. See that package's README for the full migration.

## Source

This package's source lives here, under `legacy/`, because the original repository was renamed to `mppx-condition-gate` when v2 superseded it. It is retained so the security fix has a verifiable home; it is not under active development.

## License

MIT

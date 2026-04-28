# openac-sdk

ZK proof SDK for SD-JWT credentials. Prove predicates (age >= 18, etc.) without revealing claim values.

Built on [zkID](https://github.com/privacy-scaling-explorations/zkID) (Spartan2 + Hyrax over secp256r1).

## Two-Circuit Protocol

1. **Prepare** — Verify JWT signature (ES256), extract device key, normalize claims
2. **Show** — Prove device key ownership, evaluate predicates over claims

Both proofs share a blinded witness commitment (`comm_W_shared`).

## Install

```bash
npm install openac-sdk
```

## Usage

### Prover: Precompute + Present

```typescript
import { OpenAC, PredicateOp } from "openac-sdk";

const openac = await OpenAC.init({ assetsDir: "./assets" });
const keys = await openac.loadKeysFromUrl("https://cdn.example/keys", "1k");

// Precompute (once per credential, ~2s)
const precomputed = await openac.precompute({
  jwt: sdJwtToken,
  disclosures: ["WyJzYWx0...", "..."],
  issuerPublicKey: { kty: "EC", crv: "P-256", x: "...", y: "..." },
  keys,
});

// Present (per verification, ~100ms)
const proof = await openac.present({
  precomputed,
  verifierNonce: "challenge-123",
  devicePrivateKey: "0xabcdef...",
  keys,
  showInputOptions: {
    normalizedClaimValues: [890615n],
    predicates: [{ claimRef: 0, op: PredicateOp.GE, rhsValue: 18n }],
  },
});
```

### Verifier

```typescript
const openac = await OpenAC.init();

const result = await openac.verify(proof, {
  prepareVerifyingKey: /* Uint8Array */,
  showVerifyingKey: /* Uint8Array */,
});

result.valid;            // true
result.expressionResult; // true (predicate passed)
result.deviceKey;        // { x: '0x...', y: '0x...' }
```

### Multiple Credentials

```typescript
import { OpenAC, LogicToken, PredicateOp } from "openac-sdk";

const openac = await OpenAC.init({ assetsDir: "./assets" });
const keys = await openac.loadKeysFromUrl("https://cdn.example/keys", "1k");

const prepared = await openac.precomputePreparedMulti({
  credentials: [
    { jwt: idCredential, disclosures: idDisclosures, issuerPublicKey: idIssuer },
    { jwt: membershipCredential, disclosures: membershipDisclosures, issuerPublicKey: membershipIssuer },
  ],
  keys,
});

// prepared.normalizedClaimValues is a flattened namespace:
// VC0 claim 0, VC0 claim 1, VC1 claim 0, VC1 claim 1.
```

`precomputePreparedMulti` runs the normal single-credential Prepare circuit once per credential and bundles the saved normalized claims for a future multi-credential Show. All credentials must be bound to the same `cnf.jwk` device key. Full multi-credential presentation still needs a verifier/prover update to link several Prepare commitments to one Show proof.

### One-Shot (no precompute/present split)

```typescript
const proof = await openac.createProof({
  jwt: sdJwtToken,
  disclosures,
  issuerPublicKey,
  devicePrivateKey: "0xabcdef...",
  verifierNonce: "challenge-123",
  keys,
});

const result = await openac.verifyProof(proof.serialize(), verifyingKeys);
```

## Predicates

```typescript
import { PredicateOp, LogicToken, buildShowCircuitInputs, DEFAULT_SHOW_PARAMS } from "openac-sdk";

// claim[0] >= 18 AND claim[1] == 1
const showInputs = buildShowCircuitInputs(DEFAULT_SHOW_PARAMS, nonce, sig, deviceKey, {
  normalizedClaimValues: [25n, 1n],
  predicates: [
    { claimRef: 0, op: PredicateOp.GE, rhsValue: 18n },
    { claimRef: 1, op: PredicateOp.EQ, rhsValue: 1n },
  ],
  logicExpression: [
    { type: LogicToken.REF, value: 0 },
    { type: LogicToken.REF, value: 1 },
    { type: LogicToken.AND, value: 0 },
  ],
});
```

Operators: `LE` (<=), `GE` (>=), `EQ` (==). Logic: `REF`, `AND`, `OR`, `NOT`. Evaluated as postfix RPN.

## API

| Method | Description |
|--------|-------------|
| `OpenAC.init(config?)` | Load WASM prover |
| `openac.loadKeysFromUrl(url, size)` | Fetch keys (`'1k'`/`'2k'`/`'4k'`/`'8k'`) |
| `openac.loadMultiKeysFromUrl(url, size, credentialCount?)` | Fetch legacy combined-Prepare multi-credential keys |
| `openac.loadKeys(data)` | Load keys from bytes |
| `openac.precompute(req)` | Prove JWT validity (cache this) |
| `openac.present(req)` | Prove predicates + device key |
| `openac.precomputePreparedMulti(req)` | Prepare each credential once and cache flattened claims for multi-credential Show |
| `openac.precomputeMulti(req)` | Legacy combined-Prepare multi-credential path |
| `openac.presentMulti(req)` | Legacy combined-Prepare multi-credential presentation |
| `openac.verify(proof, keys)` | Verify proof |
| `openac.createProof(req)` | One-shot prove |
| `openac.verifyProof(bytes, keys)` | Verify serialized proof |

| Utility | |
|---------|---|
| `Credential.parse(jwt, disclosures)` | Parse SD-JWT |
| `buildJwtCircuitInputs(...)` | Build Prepare circuit inputs |
| `buildShowCircuitInputs(...)` | Build Show circuit inputs |
| `signDeviceNonce(nonce, key)` | Sign verifier challenge |
| `WitnessCalculator` | Generate circom witnesses |
| `NativeBackend` | Wrap Rust CLI for server-side proving |

## Build

```bash
npm install
npm run build           # TypeScript
npm run build:wasm      # WASM prover (needs Rust + wasm-pack)
npm run build:all       # Both
npm test
```

### Generate Keys

```bash
cd ../ecdsa-spartan2
cargo build --release
cargo run --release -- prepare setup --size 1k --input ../circom/inputs/jwt/1k/default.json
cargo run --release -- show setup --size 1k --input ../circom/inputs/show/default.json
```

### Key Sizes

| Size | Prepare PK/VK | Show PK/VK | Total |
|------|---------------|------------|-------|
| 1k | 258 MB each | 3 MB each | ~522 MB |
| 2k | 427 MB each | 3 MB each | ~860 MB |
| 4k | 811 MB each | 3 MB each | ~1.6 GB |
| 8k | 1.6 GB each | 3 MB each | ~3.2 GB |

## Dependencies

`@noble/curves` (P-256 ECDSA), `@noble/hashes` (SHA-256). No Node.js-specific runtime deps.

## License

MIT

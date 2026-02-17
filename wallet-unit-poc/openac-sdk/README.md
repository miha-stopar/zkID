# openac-sdk

Privacy-preserving identity verification using zero-knowledge proofs. Create and verify ZK proofs from JWT credentials without revealing sensitive data.

## Overview

OpenAC SDK wraps the [zkID](https://github.com/privacy-scaling-explorations/zkID) proving system (Spartan2 + Hyrax over secp256r1) into a TypeScript package. It provides a high-level API for:

- **Provers (wallets/holders)**: Generate ZK proofs from SD-JWT credentials that prove age (18+) without revealing the actual birthdate
- **Verifiers (relying parties)**: Verify ZK proofs and extract public values (age above 18, device key binding)

The SDK uses a two-circuit protocol:
1. **Prepare** — Validates the JWT signature (ES256), extracts device binding key, and decodes claims
2. **Show** — Proves device key ownership via ECDSA and verifies age > 18

Both proofs share a witness commitment for privacy-preserving credential presentation.

## Installation

```bash
npm install openac-sdk
```

## Quick Start

### Prover (Wallet)

```typescript
import { OpenAC } from 'openac-sdk';

// Initialize the SDK (loads WASM module)
const openac = await OpenAC.init();

// Generate keys (one-time, computationally expensive)
const keys = await openac.setup();

// Create a zero-knowledge proof
const proof = await openac.createProof({
  jwt: sdJwtToken,                          // SD-JWT from issuer
  disclosures: ['WyJzYWx0...', ...],        // SD-JWT disclosures
  issuerPublicKey: {                         // Issuer's P-256 public key (JWK)
    kty: 'EC', crv: 'P-256',
    x: '...', y: '...'
  },
  devicePrivateKey: '0xabcdef...',           // Device ECDSA private key
  verifierNonce: 'random-challenge-123',     // Verifier's challenge
  keys,
});

// Send to verifier
const proofBytes = proof.serialize();
```

### Verifier

```typescript
import { OpenAC } from 'openac-sdk';

const openac = await OpenAC.init();

// Verify the proof
const result = await openac.verifyProof(proofBytes, {
  prepareVerifyingKey: keys.prepareVerifyingKey,
  showVerifyingKey: keys.showVerifyingKey,
});

console.log(result.valid);        // true
console.log(result.ageAbove18);   // true
console.log(result.deviceKey);    // { x: '...', y: '...' }
```

## API Reference

### `OpenAC`

| Method | Description |
|--------|-------------|
| `OpenAC.init(config?)` | Initialize SDK (loads WASM + artifacts) |
| `openac.setup()` | Generate proving/verifying keys (one-time) |
| `openac.loadKeys(data)` | Load previously saved keys |
| `openac.createProof(request)` | Create a ZK proof from a JWT credential |
| `openac.verifyProof(proof, keys)` | Verify a serialized proof bundle |
| `openac.verifyComponents(prepareProof, showProof, keys)` | Verify individual proof components |

### `Credential` (Utility)

| Method | Description |
|--------|-------------|
| `Credential.parse(jwt, disclosures)` | Parse an SD-JWT token |
| `credential.findBirthdayClaim()` | Auto-detect birthday claim index |
| `credential.deviceBindingKey` | Extract device binding key from `cnf.jwk` |
| `credential.claims` | Parsed disclosed claims |
| `credential.sdDigests` | Get `_sd` array from payload |

### Input Builders (Advanced)

For users who need low-level control over circuit inputs:

```typescript
import { buildJwtCircuitInputs, buildShowCircuitInputs, signDeviceNonce } from 'openac-sdk';

// Build JWT (Prepare) circuit inputs manually
const jwtInputs = buildJwtCircuitInputs(credential, issuerKey, params, matches, flags, bdayIdx);

// Sign a verifier nonce
const sig = signDeviceNonce(nonce, devicePrivateKey);

// Build Show circuit inputs manually
const showInputs = buildShowCircuitInputs(params, nonce, sig, deviceKey, claim, date);
```

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  openac-sdk (TypeScript, ESM)                                    │
│                                                                   │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐    │
│  │ OpenAC   │  │ Prover   │  │ Verifier │  │ Credential    │    │
│  │ (facade) │  │          │  │          │  │ (SD-JWT parse)│    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └───────────────┘    │
│       │              │              │                              │
│  ┌────▼──────────────▼──────────────▼────────────────────────┐   │
│  │  NativeBackend (wraps Rust CLI via execFile)               │   │
│  │  WitnessCalculator (circom WASM witness generation)        │   │
│  └────┬───────────────────────────────────────────────────────┘   │
│       │                                                           │
│  ┌────▼──────────────────────────────────────────────────────┐   │
│  │  Input Builders (JWT + Show circuit input generation)      │   │
│  │  Utils (base64, SHA-256, field arithmetic, encoding)       │   │
│  └────────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────────┐
│  ecdsa-spartan2 (Rust native binary)                          │
│                                                                │
│  ├── Spartan2 + Hyrax polynomial commitment (ZK-SNARK)       │
│  ├── PrepareCircuit (JWT signature + claim verification)      │
│  ├── ShowCircuit (device key ownership + age proof)           │
│  ├── Shared witness commitment (comm_W_shared)                │
│  └── witnesscalc dylibs (jwt, show, ecdsa)                   │
└──────────────────────────────────────────────────────────────────┘
```

## Native Backend

The SDK includes a `NativeBackend` class that wraps the Rust `ecdsa-spartan2` CLI binary for heavy operations (proving, verification, reblinding). This is the recommended approach for server-side/desktop usage since the proving keys are too large (~420 MB) for WASM.

```typescript
import { NativeBackend } from 'openac-sdk';

// Auto-discovers binary + dylib paths
const backend = new NativeBackend();

// Or configure explicitly
const backend = new NativeBackend({
  binaryPath: '/path/to/ecdsa-spartan2',
  workDir: '/path/to/ecdsa-spartan2/',
});

// Run the full proving pipeline (assumes keys exist)
await backend.proveAll();

// Or step by step:
await backend.generateSharedBlinds();
await backend.provePrepare();
await backend.reblindPrepare();
await backend.proveShow();
await backend.reblindShow();

// Verify
const prepResult = await backend.verifyPrepare();
const showResult = await backend.verifyShow();

// Load artifacts
const keys = await backend.loadKeys();
const proofs = await backend.loadProofs();
```

**Note on macOS**: The Rust binary links against `@rpath/libwitnesscalc_*.dylib` but has no embedded rpath. The `NativeBackend` automatically discovers and sets `DYLD_LIBRARY_PATH` to the correct build output directory. If you call the binary directly, set this yourself:

```bash
export DYLD_LIBRARY_PATH=/path/to/ecdsa-spartan2/target/release/build/ecdsa-spartan2-*/out/witnesscalc/build_witnesscalc/src
```

## Building from Source

### Prerequisites

- Node.js >= 18
- Rust toolchain (for native binary compilation; WASM compilation optional)
- Circom circuits compiled (`cd ../circom && yarn compile:all`)
- Native binary built (`cd ../ecdsa-spartan2 && cargo build --release`)

### Build Steps

```bash
# Install dependencies
npm install

# Build TypeScript SDK
npm run build

# Run tests (unit + witness + E2E)
npm test

# Type check
npm run lint
```

## Project Structure

```
openac-sdk/
├── src/
│   ├── index.ts              # Public API (OpenAC class + re-exports)
│   ├── types.ts              # All TypeScript interfaces
│   ├── errors.ts             # Error types (SetupError, ProofError, etc.)
│   ├── credential.ts         # SD-JWT parsing
│   ├── prover.ts             # Prover (orchestrates Prepare→Show pipeline)
│   ├── verifier.ts           # Verifier (checks both proofs)
│   ├── wasm-bridge.ts        # WASM module loader + typed wrapper
│   ├── utils.ts              # Base64, SHA-256, field math, encoding
│   └── inputs/
│       ├── jwt-input-builder.ts   # JWT (Prepare) circuit input generation
│       └── show-input-builder.ts  # Show circuit input generation
├── wasm/
│   ├── Cargo.toml            # Rust WASM crate (wraps ecdsa-spartan2)
│   └── src/lib.rs            # wasm-bindgen exports
├── tests/
│   ├── credential.test.ts         # 16 unit tests (SD-JWT parsing)
│   ├── witness-calculator.test.ts # 3 tests (circom WASM witness generation)
│   ├── native-backend.test.ts     # 7 tests (artifact loading)
│   └── e2e.test.ts                # 6 E2E tests (full prove + verify pipeline)
├── assets/                   # Bundled circuit artifacts (witness WASM)
├── scripts/
│   └── build-wasm.sh         # WASM build script
├── package.json
├── tsconfig.json
└── tsup.config.ts
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `@noble/curves` | P-256 ECDSA operations (signature parsing, verification) |
| `@noble/hashes` | SHA-256 hashing |

Zero Node.js-specific dependencies in the runtime. Works in browsers and Node.js.

## Test Results

All 32 tests pass:

| Test File | Tests | Description |
|-----------|-------|-------------|
| `credential.test.ts` | 16 | SD-JWT parsing, disclosure extraction, birthday detection |
| `witness-calculator.test.ts` | 3 | Circom WASM witness generation (JWT + Show circuits) |
| `native-backend.test.ts` | 7 | Artifact loading from pre-generated keys directory |
| `e2e.test.ts` | 6 | Full pipeline: witness gen, prove, reblind, verify via Rust binary |

E2E pipeline benchmarks (Apple Silicon):

| Step | Time |
|------|------|
| Generate shared blinds | ~6 ms |
| Prepare prove | ~2.1 s |
| Prepare reblind | ~1.5 s |
| Show prove | ~67 ms |
| Show reblind | ~49 ms |
| Prepare verify | ~1.8 s |
| Show verify | ~39 ms |
| **Total** | **~5.6 s** |

## License

MIT

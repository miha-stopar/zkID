# RSA Verifier Circuits — Reference

Standalone RSA-2048 and RSA-4096 signature verification circuits for RS256 JWT verification. This is a **proof-of-concept** on the [`feat/rsa-verifier-circuit`](https://github.com/moven0831/zkID/tree/feat/rsa-verifier-circuit) branch, supplementary to the primary ES256 (JWT + Show) construction.

> **Note:** The main zkID pipeline uses ES256 with shared witness commitments and reblinding for unlinkability. These RSA circuits are independent — no shared witness, no reblinding — and are provided as a reference for teams using RS256 instead of ES256.

## Overview

The RSA verifier circuit performs standalone RSA signature verification in three steps:

1. **SHA-256** — hash the padded message using `@zk-email/circuits`
2. **Bits2Limbs** — convert the 256-bit big-endian hash to little-endian `n`-bit RSA limbs
3. **RSAVerifier65537** — verify PKCS#1 v1.5 RSA-SHA256 signature against the hash

Unlike the main JWT/Show pipeline, these circuits operate independently with no shared witness commitments (`comm_w_shared`) and no reblinding support.

## Circuit Specification

### `RSAVerify(maxByteLength, n, k)`

| Parameter | Description |
|-----------|-------------|
| `maxByteLength` | Max SHA-256 padded message length in bytes (must be multiple of 64) |
| `n` | Bits per RSA limb (recommended: 121) |
| `k` | Number of RSA limbs (17 for RSA-2048, 34 for RSA-4096) |

**Inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `message[maxByteLength]` | private | SHA-256 padded message bytes |
| `messageLength` | private | Actual message length |
| `signature[k]` | private | RSA signature as `k` limbs |
| `modulus[k]` | **public** | RSA public modulus as `k` limbs |

### Helper: `Bits2Limbs(n, k, totalBits)`

Converts big-endian SHA-256 output bits to little-endian `n`-bit limbs for the RSA verifier. Maps LSB-first limb bit positions to big-endian SHA output indices.

### Concrete Instantiations

| Circuit | Template | File |
|---------|----------|------|
| RSA-2048 | `RSAVerify(64, 121, 17)` | `circuits/main/rsa_verify_2048.circom` |
| RSA-4096 | `RSAVerify(64, 121, 34)` | `circuits/main/rsa_verify_4096.circom` |

## Build & Run Commands

### Circom Compilation

From `wallet-unit-poc/circom/`:

```sh
yarn                      # install deps (includes @zk-email/circuits)
yarn generate:rsa         # generate test inputs (RSA key pair + signature)
yarn compile:rsa2048      # compile RSA-2048 circuit
yarn compile:rsa4096      # compile RSA-4096 circuit
```

### Rust CLI (Spartan2)

From `wallet-unit-poc/ecdsa-spartan2/`:

```sh
# RSA circuits require the rsa-circuits feature flag
cargo run --release --features rsa-circuits -- rsa2048 setup --input ../circom/inputs/rsa_verify_2048/default.json
cargo run --release --features rsa-circuits -- rsa2048 prove --input ../circom/inputs/rsa_verify_2048/default.json
cargo run --release --features rsa-circuits -- rsa2048 verify

cargo run --release --features rsa-circuits -- rsa4096 setup --input ../circom/inputs/rsa_verify_4096/default.json
cargo run --release --features rsa-circuits -- rsa4096 prove --input ../circom/inputs/rsa_verify_4096/default.json
cargo run --release --features rsa-circuits -- rsa4096 verify

# Full benchmark for a single circuit
cargo run --release --features rsa-circuits -- rsa2048 benchmark --input ../circom/inputs/rsa_verify_2048/default.json
cargo run --release --features rsa-circuits -- rsa4096 benchmark --input ../circom/inputs/rsa_verify_4096/default.json
```

### Feature Flags

```toml
[features]
default = ["jwt-circuit", "show-circuit"]
jwt-circuit = []
show-circuit = []
rsa-circuits = []       # opt-in, not built by default
```

**Reblind is not supported** for RSA circuits — the `shared()` and `precommitted()` trait methods return empty vectors.

## Benchmarks

**Test Device:** MacBook Pro, M4, 14-core GPU, 24GB RAM

### Circuit Characteristics

| Metric | RSA-2048 | RSA-4096 |
|--------|----------|----------|
| Wires | 215,439 | 405,962 |
| Constraints | 216,400 | 407,824 |
| Private Inputs | 82 | 99 |
| Public Inputs | 17 | 34 |

### Timing

| Operation | RSA-2048 | RSA-4096 |
|-----------|----------|----------|
| Setup | 713 ms | 2,042 ms |
| Prove | 345 ms | 767 ms |
| Verify | 33 ms | 68 ms |

### Artifact Sizes

| Artifact | RSA-2048 | RSA-4096 |
|----------|----------|----------|
| Proving Key | 65.92 MB | 174.91 MB |
| Verifying Key | 65.92 MB | 174.91 MB |
| Proof | 50.61 KB | 59.87 KB |
| Witness | 8.01 MB | 16.02 MB |

Source: [ZK-based-Human-Verification #14](https://github.com/zkmopro/ZK-based-Human-Verification/issues/14#issuecomment-3883009179)

## Key Files on Branch

All files are on the [`feat/rsa-verifier-circuit`](https://github.com/moven0831/zkID/tree/feat/rsa-verifier-circuit) branch.

| File | Description |
|------|-------------|
| `circom/circuits/rsa_verify.circom` | `RSAVerify` and `Bits2Limbs` circuit templates |
| `circom/circuits/main/rsa_verify_2048.circom` | RSA-2048 instantiation (`k=17`) |
| `circom/circuits/main/rsa_verify_4096.circom` | RSA-4096 instantiation (`k=34`) |
| `circom/inputs/rsa_verify_2048/default.json` | Test inputs for RSA-2048 |
| `circom/inputs/rsa_verify_4096/default.json` | Test inputs for RSA-4096 |
| `circom/src/generate_rsa_inputs.ts` | Input generator (RSA key pair + PKCS#1 v1.5 signature) |
| `ecdsa-spartan2/src/circuits/rsa_verify_circuit.rs` | Rust `SpartanCircuit<E>` implementation |
| `ecdsa-spartan2/Cargo.toml` | Feature flags (`rsa-circuits`) |
| `ecdsa-spartan2/src/main.rs` | CLI commands for `rsa2048` / `rsa4096` |

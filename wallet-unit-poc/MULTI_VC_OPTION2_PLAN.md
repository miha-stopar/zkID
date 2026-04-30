# Prepared Multi-VC Architecture

This is the current multi-credential design. The older prototype used one
combined two-credential Prepare circuit and SDK calls that prepared/presented a
multi proof in one batch. That path has been removed.

## Shape

Prepared multi-credential presentation uses:

1. One normal single-credential Prepare proof per credential.
2. One Link proof over the flattened prepared public values.
3. One multi-credential Show proof over the same flattened value vector.

The shared vector is:

```text
[deviceKeyX, deviceKeyY, flattenedClaimValues...]
```

The flattened claim namespace is credential-major:

```text
VC0 claim 0, VC0 claim 1, VC1 claim 0, VC1 claim 1, ...
```

## Why Link Exists

Spartan present/verify links exactly two proofs by comparing the commitment to
their shared witness vector. In the single-credential flow those two proofs are
Prepare and Show.

In the prepared multi-credential flow there are several independent Prepare
proofs, each with its own shared vector:

```text
Prepare(VC0): [deviceKeyX, deviceKeyY, VC0 claims...]
Prepare(VC1): [deviceKeyX, deviceKeyY, VC1 claims...]
Show multi:   [deviceKeyX, deviceKeyY, VC0 claims..., VC1 claims...]
```

Those vectors cannot be compared directly because their lengths and contents are
not the same. Link creates one proof with the same shared vector as Show, while
its public inputs are checked against the verified Prepare outputs. That lets
the existing Spartan bridge keep using its generic two-proof present/verify API:
Link occupies the generic "prepare side" and Show occupies the "show side".

## Verifier Binding

The verifier must not accept prover-selected proof metadata as policy. Prepared
multi verification therefore requires explicit verifier expectations:

- expected credential count
- verifier nonce
- expected Show parameters
- expected predicate program and logic expression
- optional expected per-credential claim count

The Show circuit exposes the challenge hash and predicate program as public
values. Verification recomputes those public values from verifier expectations
and rejects mismatches. This binds the proof to the verifier's requested count,
policy, claim namespace, and challenge rather than to prover-provided metadata.

## Active SDK Flow

```typescript
const prepared = await openac.precomputePreparedMulti({
  credentials,
  keys,
});

const verifierNonce = buildPreparedMultiVerifierNonce({
  nonce,
  credentialCount: 3,
  claimsPerCredential: 2,
  showParams,
  showInputOptions,
});

const proof = await openac.presentPreparedMulti({
  prepared,
  verifierNonce,
  devicePrivateKey,
  keys,
  showParams,
  showInputOptions,
});

const result = await openac.verifyPreparedMulti(
  proof,
  keys.preparedMultiVerifyingKeys(),
  {
    expectedCredentialCount: 3,
    verifierNonce,
    showParams,
    showInputOptions,
    expectedKeySetId: "1k-prepared-multi-3",
  },
);
```

Supported prepared multi counts are currently 2, 3, and 4 credentials.

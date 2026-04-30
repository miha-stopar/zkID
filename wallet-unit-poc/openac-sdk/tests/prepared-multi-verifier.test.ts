import { describe, expect, it, vi } from "vitest";

import { Verifier } from "../src/verifier.js";
import {
  buildShowPolicyPublicValues,
  deserializePreparedMultiPresentation,
  LogicToken,
  PredicateOp,
} from "../src/index.js";
import type { WasmBridge } from "../src/wasm-bridge.js";
import type {
  PreparedMultiPresentationProof,
  PreparedMultiVerificationOptions,
  PreparedMultiVerifyingKeys,
  ShowCircuitParams,
} from "../src/types.js";

const keys: PreparedMultiVerifyingKeys = {
  prepareVerifyingKey: new Uint8Array([1]),
  showVerifyingKey: new Uint8Array([2]),
  linkVerifyingKey: new Uint8Array([3]),
  credentialCount: 3,
  keySetId: "1k-prepared-multi-3",
};

const prepareProofs = [
  new Uint8Array([10]),
  new Uint8Array([11]),
  new Uint8Array([12]),
];
const linkProof = new Uint8Array([20]);
const showProof = new Uint8Array([30]);
const verifierNonce = "challenge-123";
const showParams: ShowCircuitParams = {
  nClaims: 6,
  maxPredicates: 2,
  maxLogicTokens: 8,
  valueBits: 64,
};
const showInputOptions = {
  predicates: [
    { claimRef: 1, op: PredicateOp.GE, rhsValue: 18n },
    { claimRef: 5, op: PredicateOp.EQ, rhsValue: 1n },
  ],
  logicExpression: [
    { type: LogicToken.REF, value: 0 },
    { type: LogicToken.REF, value: 1 },
    { type: LogicToken.AND, value: 0 },
  ],
};
const expected: PreparedMultiVerificationOptions = {
  expectedCredentialCount: 3,
  verifierNonce,
  showParams,
  showInputOptions,
  expectedKeySetId: "1k-prepared-multi-3",
};

function expectedLinkPublicValues(): string[] {
  return [
    "1",
    "111",
    "222",
    "10",
    "20",
    "30",
    "40",
    "50",
    "60",
    "111",
    "222",
    "10",
    "20",
    "30",
    "40",
    "50",
    "60",
  ];
}

function expectedShowPublicValues(
  expressionResult = "1",
  deviceKeyX = "111",
  deviceKeyY = "222",
): string[] {
  return [
    expressionResult,
    deviceKeyX,
    deviceKeyY,
    ...buildShowPolicyPublicValues(
      showParams,
      verifierNonce,
      showInputOptions,
    ).map((value) => value.toString()),
  ];
}

function makeProof(
  overrides: Partial<PreparedMultiPresentationProof> = {},
): PreparedMultiPresentationProof {
  return {
    kind: "multi-vc-3",
    credentialCount: 3,
    claimsPerCredential: 2,
    prepareProofs,
    linkProof,
    linkInstance: new Uint8Array([50]),
    showProof,
    showInstance: new Uint8Array([60]),
    publicValues: {
      expressionResult: true,
      deviceKeyX: "111",
      deviceKeyY: "222",
      normalizedClaimValues: [10n, 20n, 30n, 40n, 50n, 60n],
    },
    timing: {
      showWitnessMs: 0,
      showProveMs: 0,
      presentMs: 0,
      totalMs: 0,
    },
    serialize: () => new Uint8Array(),
    toBase64: () => "",
    toJSON: () => ({}) as ReturnType<PreparedMultiPresentationProof["toJSON"]>,
    ...overrides,
  };
}

function makeBridge(
  publicValuesByProofByte: Map<number, string[]> = new Map([
    [10, ["10", "20", "111", "222"]],
    [11, ["30", "40", "111", "222"]],
    [12, ["50", "60", "111", "222"]],
    [20, expectedLinkPublicValues()],
    [30, expectedShowPublicValues()],
  ]),
  sharedCommitmentMatches = true,
): WasmBridge {
  const publicValuesFor = (proof: Uint8Array): string[] => {
    const proofId = proof[0];
    if (proofId === undefined || !publicValuesByProofByte.has(proofId)) {
      throw new Error(`unknown proof ${proofId ?? "empty"}`);
    }
    return publicValuesByProofByte.get(proofId)!;
  };

  return {
    verifySingle: vi.fn(async (proof: Uint8Array) => {
      return {
        valid: true,
        publicValues: publicValuesFor(proof),
      };
    }),
    verify: vi.fn(async (link: Uint8Array, _linkVk: Uint8Array, _linkInstance: Uint8Array, show: Uint8Array) => {
      if (!sharedCommitmentMatches) {
        return {
          valid: false,
          preparePublicValues: [],
          showPublicValues: [],
          error: "Shared commitment mismatch: prepare and show proofs do not share the same private data",
        };
      }
      return {
        valid: true,
        preparePublicValues: publicValuesFor(link),
        showPublicValues: publicValuesFor(show),
      };
    }),
    compareCommWShared: vi.fn(() => sharedCommitmentMatches),
  } as unknown as WasmBridge;
}

describe("Verifier.verifyPreparedMulti", () => {
  it("accepts a linked 3VC presentation with matching Prepare, Link, and Show public values", async () => {
    const bridge = makeBridge();
    const verifier = new Verifier(bridge);

    const result = await verifier.verifyPreparedMulti(makeProof(), keys, expected);

    expect(result.valid).toBe(true);
    expect(result.expressionResult).toBe(true);
    expect(result.deviceKey).toEqual({ x: "111", y: "222" });
    expect(bridge.verifySingle).toHaveBeenCalledTimes(3);
    expect(bridge.verify).toHaveBeenCalledWith(
      new Uint8Array([20]),
      keys.linkVerifyingKey,
      new Uint8Array([50]),
      new Uint8Array([30]),
      keys.showVerifyingKey,
      new Uint8Array([60]),
    );
    expect(bridge.compareCommWShared).not.toHaveBeenCalled();
  });

  it("rejects a presentation whose Link proof is not tied to the Show proof", async () => {
    const verifier = new Verifier(makeBridge(undefined, false));

    const result = await verifier.verifyPreparedMulti(makeProof(), keys, expected);

    expect(result.valid).toBe(false);
    expect(result.error).toContain("Shared commitment mismatch");
    expect(result.error).toContain("link and show proofs");
  });

  it("rejects malformed presentation metadata before proof verification", async () => {
    const bridge = makeBridge();
    const verifier = new Verifier(bridge);

    const result = await verifier.verifyPreparedMulti(
      makeProof({
        publicValues: {
          expressionResult: true,
          deviceKeyX: "111",
          deviceKeyY: "222",
          normalizedClaimValues: [10n, 20n],
        },
      }),
      keys,
      expected,
    );

    expect(result.valid).toBe(false);
    expect(result.error).toContain(
      "Prepared multi proof public normalized claim count mismatch",
    );
    expect(bridge.verifySingle).not.toHaveBeenCalled();
  });

  it("rejects a Link proof whose public values do not match the Prepare outputs", async () => {
    const linkValues = expectedLinkPublicValues();
    linkValues[5] = "999";
    const publicValues = new Map<number, string[]>([
      [10, ["10", "20", "111", "222"]],
      [11, ["30", "40", "111", "222"]],
      [12, ["50", "60", "111", "222"]],
      [20, linkValues],
      [30, expectedShowPublicValues()],
    ]);
    const verifier = new Verifier(makeBridge(publicValues));

    const result = await verifier.verifyPreparedMulti(makeProof(), keys, expected);

    expect(result.valid).toBe(false);
    expect(result.error).toBe("Link proof public value mismatch at index 5");
  });

  it("rejects a Show proof whose device key does not match the prepared credentials", async () => {
    const publicValues = new Map<number, string[]>([
      [10, ["10", "20", "111", "222"]],
      [11, ["30", "40", "111", "222"]],
      [12, ["50", "60", "111", "222"]],
      [20, expectedLinkPublicValues()],
      [30, expectedShowPublicValues("1", "111", "999")],
    ]);
    const verifier = new Verifier(makeBridge(publicValues));

    const result = await verifier.verifyPreparedMulti(makeProof(), keys, expected);

    expect(result.valid).toBe(false);
    expect(result.error).toBe(
      "Show proof device key does not match prepared credentials",
    );
  });

  it("rejects malformed Prepare public values instead of padding missing fields", async () => {
    const publicValues = new Map<number, string[]>([
      [10, ["10", "20", "111"]],
      [11, ["30", "40", "111", "222"]],
      [12, ["50", "60", "111", "222"]],
      [20, expectedLinkPublicValues()],
      [30, expectedShowPublicValues()],
    ]);
    const verifier = new Verifier(makeBridge(publicValues));

    const result = await verifier.verifyPreparedMulti(makeProof(), keys, expected);

    expect(result.valid).toBe(false);
    expect(result.error).toContain("Prepare proof 0 public value count mismatch");
  });

  it("rejects prepared credentials with different device keys", async () => {
    const publicValues = new Map<number, string[]>([
      [10, ["10", "20", "111", "222"]],
      [11, ["30", "40", "111", "999"]],
      [12, ["50", "60", "111", "222"]],
      [20, expectedLinkPublicValues()],
      [30, expectedShowPublicValues()],
    ]);
    const verifier = new Verifier(makeBridge(publicValues));

    const result = await verifier.verifyPreparedMulti(makeProof(), keys, expected);

    expect(result.valid).toBe(false);
    expect(result.error).toBe("Prepare proof 1 uses a different device key");
  });

  it("converts WASM verification exceptions into invalid verification results", async () => {
    const bridge = makeBridge(new Map([[10, ["10", "20", "111", "222"]]]));
    const verifier = new Verifier(bridge);

    const result = await verifier.verifyPreparedMulti(makeProof(), keys, expected);

    expect(result.valid).toBe(false);
    expect(result.error).toContain("Prepare proof verification failed");
    expect(result.error).toContain("unknown proof 11");
  });

  it("rejects a proof that self-selects a lower credential count than expected", async () => {
    const bridge = makeBridge();
    const verifier = new Verifier(bridge);

    const result = await verifier.verifyPreparedMulti(
      makeProof({
        kind: "multi-vc-2",
        credentialCount: 2,
        prepareProofs: [prepareProofs[0]!, prepareProofs[1]!],
        publicValues: {
          expressionResult: true,
          deviceKeyX: "111",
          deviceKeyY: "222",
          normalizedClaimValues: [10n, 20n, 30n, 40n],
        },
      }),
      keys,
      expected,
    );

    expect(result.valid).toBe(false);
    expect(result.error).toContain("credential count mismatch");
    expect(bridge.verifySingle).not.toHaveBeenCalled();
  });

  it("rejects mismatched prepared multi verifying key count", async () => {
    const bridge = makeBridge();
    const verifier = new Verifier(bridge);

    const result = await verifier.verifyPreparedMulti(
      makeProof(),
      { ...keys, credentialCount: 2 },
      expected,
    );

    expect(result.valid).toBe(false);
    expect(result.error).toContain("verifying key count mismatch");
    expect(bridge.verifySingle).not.toHaveBeenCalled();
  });

  it("rejects mismatched prepared multi key set id", async () => {
    const bridge = makeBridge();
    const verifier = new Verifier(bridge);

    const result = await verifier.verifyPreparedMulti(
      makeProof(),
      { ...keys, keySetId: "1k-prepared-multi-2" },
      expected,
    );

    expect(result.valid).toBe(false);
    expect(result.error).toContain("verifying key set mismatch");
    expect(bridge.verifySingle).not.toHaveBeenCalled();
  });

  it("rejects a Show proof with a different challenge or policy", async () => {
    const wrongPolicyValues = expectedShowPublicValues();
    wrongPolicyValues[3] = "999";
    const publicValues = new Map<number, string[]>([
      [10, ["10", "20", "111", "222"]],
      [11, ["30", "40", "111", "222"]],
      [12, ["50", "60", "111", "222"]],
      [20, expectedLinkPublicValues()],
      [30, wrongPolicyValues],
    ]);
    const verifier = new Verifier(makeBridge(publicValues));

    const result = await verifier.verifyPreparedMulti(makeProof(), keys, expected);

    expect(result.valid).toBe(false);
    expect(result.error).toBe("Show proof challenge/policy public value mismatch at index 0");
  });

  it("round-trips serialized prepared multi presentations", () => {
    const serialized = new TextEncoder().encode(
      JSON.stringify({
        version: "0.1.0",
        kind: "multi-vc-3",
        credentialCount: 3,
        claimsPerCredential: 2,
        prepareProofs: ["Cg==", "Cw==", "DA=="],
        linkProof: "FA==",
        linkInstance: "Mg==",
        showProof: "Hg==",
        showInstance: "PA==",
        publicValues: {
          expressionResult: true,
          deviceKeyX: "111",
          deviceKeyY: "222",
          normalizedClaimValues: ["10", "20", "30", "40", "50", "60"],
        },
      }),
    );

    const proof = deserializePreparedMultiPresentation(serialized);
    const roundTripped = deserializePreparedMultiPresentation(proof.serialize());

    expect(proof.toJSON().prepareProofs).toEqual(["Cg==", "Cw==", "DA=="]);
    expect(proof.toBase64().length).toBeGreaterThan(0);
    expect(roundTripped.kind).toBe("multi-vc-3");
    expect(roundTripped.prepareProofs[1]).toEqual(new Uint8Array([11]));
    expect(roundTripped.linkProof).toEqual(new Uint8Array([20]));
    expect(roundTripped.showProof).toEqual(new Uint8Array([30]));
    expect(roundTripped.publicValues.normalizedClaimValues).toEqual([
      10n,
      20n,
      30n,
      40n,
      50n,
      60n,
    ]);
  });
});

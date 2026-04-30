import { WasmBridge } from "./wasm-bridge.js";
import { deserializeProofBundle } from "./prover.js";
import { getPreparedMultiShowCircuitProfile } from "./multi-circuit.js";
import {
  buildShowPolicyPublicValues,
  showPolicyPublicValueCount,
} from "./inputs/show-input-builder.js";
import type {
  PreparedMultiPresentationProof,
  PreparedMultiVerificationOptions,
  PreparedMultiVerifyingKeys,
  VerificationResult,
  VerifyingKeys,
  SerializedProof,
} from "./types.js";

function parseScalarToBool(value: string): boolean {
  if (!value) return false;
  const cleaned = value.replace(/^0x/, "").replace(/[^0-9a-fA-F]/g, "");
  if (!cleaned) return false;
  if (/^0+$/.test(cleaned)) return false;
  return true;
}

function normalizeScalar(value: string): string {
  const cleaned = value.replace(/^0x/, "").replace(/[^0-9a-fA-F]/g, "");
  return cleaned.replace(/^0+/, "") || "0";
}

export class Verifier {
  private bridge: WasmBridge;

  constructor(bridge: WasmBridge) {
    this.bridge = bridge;
  }

  async verifyProof(
    proof: SerializedProof,
    keys: VerifyingKeys,
  ): Promise<VerificationResult> {
    const startTime = performance.now();

    let bundle;
    try {
      bundle = deserializeProofBundle(proof);
    } catch {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: "Invalid proof format",
      };
    }

    const result = await this.bridge.verify(
      bundle.prepareProof,
      keys.prepareVerifyingKey,
      bundle.prepareInstance,
      bundle.showProof,
      keys.showVerifyingKey,
      bundle.showInstance,
    );

    if (!result.valid) {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: result.error ?? "Proof verification failed",
      };
    }

    const expressionResult = parseScalarToBool(result.showPublicValues[0] ?? "");

    return {
      valid: true,
      expressionResult,
      deviceKey: {
        x: result.showPublicValues[1] ?? "",
        y: result.showPublicValues[2] ?? "",
      },
      verifyMs: performance.now() - startTime,
    };
  }

  async verifyComponents(
    prepareProof: Uint8Array,
    showProof: Uint8Array,
    keys: VerifyingKeys,
    prepareInstance: Uint8Array,
    showInstance: Uint8Array,
  ): Promise<VerificationResult> {
    const startTime = performance.now();

    const result = await this.bridge.verify(
      prepareProof,
      keys.prepareVerifyingKey,
      prepareInstance,
      showProof,
      keys.showVerifyingKey,
      showInstance,
    );

    if (!result.valid) {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: result.error ?? "Proof verification failed",
      };
    }

    const expressionResult = parseScalarToBool(result.showPublicValues[0] ?? "");

    return {
      valid: true,
      expressionResult,
      deviceKey: {
        x: result.showPublicValues[1] ?? "",
        y: result.showPublicValues[2] ?? "",
      },
      verifyMs: performance.now() - startTime,
    };
  }

  async verifyPreparedMulti(
    proof: PreparedMultiPresentationProof,
    keys: PreparedMultiVerifyingKeys,
    expected: PreparedMultiVerificationOptions,
  ): Promise<VerificationResult> {
    const startTime = performance.now();

    if (!expected || !Number.isInteger(expected.expectedCredentialCount)) {
      return this.invalidResult(
        startTime,
        "Prepared multi verification requires an expected credential count",
      );
    }
    if (!expected.verifierNonce) {
      return this.invalidResult(
        startTime,
        "Prepared multi verification requires the expected verifier nonce",
      );
    }
    const policyError = this.validateExpectedPolicy(expected);
    if (policyError) {
      return this.invalidResult(startTime, policyError);
    }

    let profile;
    try {
      profile = getPreparedMultiShowCircuitProfile(expected.expectedCredentialCount);
    } catch (error) {
      return this.invalidResult(startTime, error instanceof Error ? error.message : String(error));
    }

    if (proof.credentialCount !== expected.expectedCredentialCount) {
      return this.invalidResult(
        startTime,
        `Prepared multi proof credential count mismatch: expected ${expected.expectedCredentialCount}`,
      );
    }
    if (
      keys.credentialCount !== undefined &&
      keys.credentialCount !== expected.expectedCredentialCount
    ) {
      return this.invalidResult(
        startTime,
        `Prepared multi verifying key count mismatch: expected ${expected.expectedCredentialCount}`,
      );
    }
    if (expected.expectedKeySetId !== undefined) {
      if (!keys.keySetId) {
        return this.invalidResult(
          startTime,
          "Prepared multi verification requires verifying keys with keySetId metadata",
        );
      }
      if (keys.keySetId !== expected.expectedKeySetId) {
        return this.invalidResult(
          startTime,
          `Prepared multi verifying key set mismatch: expected ${expected.expectedKeySetId}`,
        );
      }
    }

    if (proof.kind !== profile.kind) {
      return this.invalidResult(
        startTime,
        "Prepared multi proof kind does not match credential count",
      );
    }

    if (
      !Number.isInteger(proof.claimsPerCredential) ||
      proof.claimsPerCredential <= 0
    ) {
      return this.invalidResult(
        startTime,
        "Prepared multi proof has an invalid claimsPerCredential value",
      );
    }

    const expectedClaimsPerCredential =
      expected.expectedClaimsPerCredential ??
      profile.defaultShowParams.nClaims / profile.credentialCount;
    if (proof.claimsPerCredential !== expectedClaimsPerCredential) {
      return this.invalidResult(
        startTime,
        `Prepared multi proof claimsPerCredential mismatch: expected ${expectedClaimsPerCredential}`,
      );
    }

    const expectedClaimCount = proof.credentialCount * proof.claimsPerCredential;
    const showParams = expected.showParams ?? profile.defaultShowParams;
    if (showParams.nClaims !== expectedClaimCount) {
      return this.invalidResult(
        startTime,
        `Expected Show nClaims (${showParams.nClaims}) does not match prepared normalized claim count (${expectedClaimCount})`,
      );
    }

    let expectedShowPolicyPublicValues: bigint[];
    try {
      expectedShowPolicyPublicValues = buildShowPolicyPublicValues(
        showParams,
        expected.verifierNonce,
        expected.showInputOptions,
      );
    } catch (error) {
      return this.invalidResult(
        startTime,
        `Invalid expected Show policy: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    const expectedPolicyPublicCount = showPolicyPublicValueCount(showParams);
    if (expectedShowPolicyPublicValues.length !== expectedPolicyPublicCount) {
      return this.invalidResult(
        startTime,
        "Expected Show policy public value count mismatch",
      );
    }

    const normalizedClaimValues = proof.publicValues?.normalizedClaimValues;
    if (
      !Array.isArray(normalizedClaimValues) ||
      normalizedClaimValues.length !== expectedClaimCount
    ) {
      return this.invalidResult(
        startTime,
        `Prepared multi proof public normalized claim count mismatch: expected ${expectedClaimCount}`,
      );
    }

    if (
      proof.prepareProofs.length !== proof.credentialCount
    ) {
      return this.invalidResult(
        startTime,
        "Prepared multi proof has an invalid Prepare proof count",
      );
    }

    const preparePublicValues: string[][] = [];
    for (const prepareProof of proof.prepareProofs) {
      let result;
      try {
        result = await this.bridge.verifySingle(
          prepareProof,
          keys.prepareVerifyingKey,
        );
      } catch (error) {
        return this.invalidResult(
          startTime,
          `Prepare proof verification failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      if (!result.valid) {
        return this.invalidResult(startTime, "Prepare proof verification failed");
      }
      preparePublicValues.push(result.publicValues);
    }

    let linkedResult;
    try {
      linkedResult = await this.bridge.verify(
        proof.linkProof,
        keys.linkVerifyingKey,
        proof.linkInstance,
        proof.showProof,
        keys.showVerifyingKey,
        proof.showInstance,
      );
    } catch (error) {
      return this.invalidResult(
        startTime,
        `Link/Show proof verification failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (!linkedResult.valid) {
      return this.invalidResult(
        startTime,
        linkedResult.error
          ? this.formatLinkShowVerificationError(linkedResult.error)
          : "Link/Show proof verification failed",
      );
    }

    const linkPublicValues = linkedResult.preparePublicValues;
    const showPublicValues = linkedResult.showPublicValues;

    let expectedPublic: string[];
    try {
      expectedPublic = this.expectedLinkPublicValues(
        preparePublicValues,
        proof.claimsPerCredential,
      );
    } catch (error) {
      return this.invalidResult(
        startTime,
        error instanceof Error ? error.message : String(error),
      );
    }
    const expectedNormalizedClaims = expectedPublic.slice(3, 3 + expectedClaimCount);
    for (let i = 0; i < expectedNormalizedClaims.length; i++) {
      if (
        normalizeScalar(normalizedClaimValues[i]?.toString() ?? "") !==
        normalizeScalar(expectedNormalizedClaims[i] ?? "")
      ) {
        return this.invalidResult(
          startTime,
          `Prepared multi proof public normalized claim mismatch at index ${i}`,
        );
      }
    }

    const actualPublic = linkPublicValues;
    if (actualPublic.length !== expectedPublic.length) {
      return this.invalidResult(
        startTime,
        "Link proof public value count mismatch",
      );
    }

    for (let i = 0; i < expectedPublic.length; i++) {
      if (normalizeScalar(actualPublic[i] ?? "") !== normalizeScalar(expectedPublic[i] ?? "")) {
        return this.invalidResult(
          startTime,
          `Link proof public value mismatch at index ${i}`,
        );
      }
    }

    if (showPublicValues.length < 3) {
      return this.invalidResult(
        startTime,
        "Show proof public value count mismatch",
      );
    }

    const expectedShowPublicCount = 3 + expectedShowPolicyPublicValues.length;
    if (showPublicValues.length !== expectedShowPublicCount) {
      return this.invalidResult(
        startTime,
        `Show proof public value count mismatch: expected ${expectedShowPublicCount}, got ${showPublicValues.length}`,
      );
    }

    if (
      normalizeScalar(showPublicValues[1] ?? "") !==
        normalizeScalar(expectedPublic[1] ?? "") ||
      normalizeScalar(showPublicValues[2] ?? "") !==
        normalizeScalar(expectedPublic[2] ?? "")
    ) {
      return this.invalidResult(
        startTime,
        "Show proof device key does not match prepared credentials",
      );
    }

    for (let i = 0; i < expectedShowPolicyPublicValues.length; i++) {
      if (
        normalizeScalar(showPublicValues[3 + i] ?? "") !==
        normalizeScalar(expectedShowPolicyPublicValues[i]!.toString())
      ) {
        return this.invalidResult(
          startTime,
          `Show proof challenge/policy public value mismatch at index ${i}`,
        );
      }
    }

    const expressionResult = parseScalarToBool(showPublicValues[0] ?? "");
    if (expected.requireExpressionResult !== false && !expressionResult) {
      return this.invalidResult(
        startTime,
        "Show proof expression result does not satisfy the expected policy",
      );
    }

    return {
      valid: true,
      expressionResult,
      deviceKey: {
        x: showPublicValues[1] ?? "",
        y: showPublicValues[2] ?? "",
      },
      verifyMs: performance.now() - startTime,
    };
  }

  private invalidResult(startTime: number, error: string): VerificationResult {
    return {
      valid: false,
      expressionResult: null,
      deviceKey: null,
      verifyMs: performance.now() - startTime,
      error,
    };
  }

  private formatLinkShowVerificationError(error: string): string {
    return error
      .replace("prepare and show proofs", "link and show proofs")
      .replace("Prepare proof", "Link proof");
  }

  private validateExpectedPolicy(
    expected: PreparedMultiVerificationOptions,
  ): string | null {
    const options = expected.showInputOptions;
    if (!options || !Array.isArray(options.predicates) || options.predicates.length === 0) {
      return "Prepared multi verification requires explicit expected predicates";
    }
    if (
      !Array.isArray(options.logicExpression) ||
      options.logicExpression.length === 0
    ) {
      return "Prepared multi verification requires an explicit expected logic expression";
    }
    return null;
  }

  private expectedLinkPublicValues(
    preparePublicValues: string[][],
    claimsPerCredential: number,
  ): string[] {
    if (preparePublicValues.length === 0) {
      throw new Error("Prepared multi proof has no Prepare public values");
    }
    const preparePublicValueCount = claimsPerCredential + 2;
    const first = preparePublicValues[0] ?? [];
    if (first.length !== preparePublicValueCount) {
      throw new Error(
        `Prepare proof 0 public value count mismatch: expected ${preparePublicValueCount}, got ${first.length}`,
      );
    }
    const deviceKeyX = first[claimsPerCredential] ?? "";
    const deviceKeyY = first[claimsPerCredential + 1] ?? "";
    const flattenedClaims: string[] = [];

    for (const [index, publicValues] of preparePublicValues.entries()) {
      if (publicValues.length !== preparePublicValueCount) {
        throw new Error(
          `Prepare proof ${index} public value count mismatch: expected ${preparePublicValueCount}, got ${publicValues.length}`,
        );
      }
      const x = publicValues[claimsPerCredential] ?? "";
      const y = publicValues[claimsPerCredential + 1] ?? "";
      if (
        normalizeScalar(x) !== normalizeScalar(deviceKeyX) ||
        normalizeScalar(y) !== normalizeScalar(deviceKeyY)
      ) {
        throw new Error(`Prepare proof ${index} uses a different device key`);
      }
      flattenedClaims.push(...publicValues.slice(0, claimsPerCredential));
    }

    return [
      "1",
      deviceKeyX,
      deviceKeyY,
      ...flattenedClaims,
      deviceKeyX,
      deviceKeyY,
      ...flattenedClaims,
    ];
  }
}

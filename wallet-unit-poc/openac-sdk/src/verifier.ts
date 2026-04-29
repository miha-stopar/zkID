import { WasmBridge } from "./wasm-bridge.js";
import { deserializeProofBundle } from "./prover.js";
import { getPreparedMultiShowCircuitProfile } from "./multi-circuit.js";
import type {
  PreparedMultiPresentationProof,
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
  ): Promise<VerificationResult> {
    const startTime = performance.now();

    let profile;
    try {
      profile = getPreparedMultiShowCircuitProfile(proof.credentialCount);
    } catch (error) {
      return this.invalidResult(startTime, error instanceof Error ? error.message : String(error));
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

    const expectedClaimCount = proof.credentialCount * proof.claimsPerCredential;
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
      proof.prepareProofs.length !== proof.credentialCount ||
      proof.prepareInstances.length !== proof.credentialCount
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

    return {
      valid: true,
      expressionResult: parseScalarToBool(showPublicValues[0] ?? ""),
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

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

    let linkResult;
    try {
      linkResult = await this.bridge.verifySingle(
        proof.linkProof,
        keys.linkVerifyingKey,
      );
    } catch (error) {
      return this.invalidResult(
        startTime,
        `Link proof verification failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (!linkResult.valid) {
      return this.invalidResult(startTime, "Link proof verification failed");
    }

    let showResult;
    try {
      showResult = await this.bridge.verifySingle(
        proof.showProof,
        keys.showVerifyingKey,
      );
    } catch (error) {
      return this.invalidResult(
        startTime,
        `Show proof verification failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (!showResult.valid) {
      return this.invalidResult(startTime, "Show proof verification failed");
    }

    let sharedCommitmentsMatch;
    try {
      sharedCommitmentsMatch = this.bridge.compareCommWShared(
        proof.linkInstance,
        proof.showInstance,
      );
    } catch (error) {
      return this.invalidResult(
        startTime,
        `Shared commitment comparison failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    if (!sharedCommitmentsMatch) {
      return this.invalidResult(
        startTime,
        "Shared commitment mismatch: link and show proofs do not share the same private claims",
      );
    }

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
    const actualPublic = linkResult.publicValues;
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

    if (showResult.publicValues.length < 3) {
      return this.invalidResult(
        startTime,
        "Show proof public value count mismatch",
      );
    }

    if (
      normalizeScalar(showResult.publicValues[1] ?? "") !==
        normalizeScalar(expectedPublic[1] ?? "") ||
      normalizeScalar(showResult.publicValues[2] ?? "") !==
        normalizeScalar(expectedPublic[2] ?? "")
    ) {
      return this.invalidResult(
        startTime,
        "Show proof device key does not match prepared credentials",
      );
    }

    return {
      valid: true,
      expressionResult: parseScalarToBool(showResult.publicValues[0] ?? ""),
      deviceKey: {
        x: showResult.publicValues[1] ?? "",
        y: showResult.publicValues[2] ?? "",
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

import { WasmBridge } from "./wasm-bridge.js";
import { deserializeProofBundle } from "./prover.js";
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

    if (
      proof.prepareProofs.length !== proof.credentialCount ||
      proof.prepareInstances.length !== proof.credentialCount
    ) {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: "Prepared multi proof has an invalid Prepare proof count",
      };
    }

    const preparePublicValues: string[][] = [];
    for (const prepareProof of proof.prepareProofs) {
      const result = await this.bridge.verifySingle(
        prepareProof,
        keys.prepareVerifyingKey,
      );
      if (!result.valid) {
        return {
          valid: false,
          expressionResult: null,
          deviceKey: null,
          verifyMs: performance.now() - startTime,
          error: "Prepare proof verification failed",
        };
      }
      preparePublicValues.push(result.publicValues);
    }

    const linkResult = await this.bridge.verifySingle(
      proof.linkProof,
      keys.linkVerifyingKey,
    );
    if (!linkResult.valid) {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: "Link proof verification failed",
      };
    }

    const showResult = await this.bridge.verifySingle(
      proof.showProof,
      keys.showVerifyingKey,
    );
    if (!showResult.valid) {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: "Show proof verification failed",
      };
    }

    if (!this.bridge.compareCommWShared(proof.linkInstance, proof.showInstance)) {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: "Shared commitment mismatch: link and show proofs do not share the same private claims",
      };
    }

    let expectedPublic: string[];
    try {
      expectedPublic = this.expectedLinkPublicValues(
        preparePublicValues,
        proof.claimsPerCredential,
      );
    } catch (error) {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
      };
    }
    const actualPublic = linkResult.publicValues;
    if (actualPublic.length !== expectedPublic.length) {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: "Link proof public value count mismatch",
      };
    }

    for (let i = 0; i < expectedPublic.length; i++) {
      if (normalizeScalar(actualPublic[i] ?? "") !== normalizeScalar(expectedPublic[i] ?? "")) {
        return {
          valid: false,
          expressionResult: null,
          deviceKey: null,
          verifyMs: performance.now() - startTime,
          error: `Link proof public value mismatch at index ${i}`,
        };
      }
    }

    if (
      normalizeScalar(showResult.publicValues[1] ?? "") !==
        normalizeScalar(expectedPublic[1] ?? "") ||
      normalizeScalar(showResult.publicValues[2] ?? "") !==
        normalizeScalar(expectedPublic[2] ?? "")
    ) {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: "Show proof device key does not match prepared credentials",
      };
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

  private expectedLinkPublicValues(
    preparePublicValues: string[][],
    claimsPerCredential: number,
  ): string[] {
    const first = preparePublicValues[0] ?? [];
    const deviceKeyX = first[claimsPerCredential] ?? "";
    const deviceKeyY = first[claimsPerCredential + 1] ?? "";
    const flattenedClaims: string[] = [];

    for (const [index, publicValues] of preparePublicValues.entries()) {
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

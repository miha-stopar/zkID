import { WasmBridge, VcSize } from "./wasm-bridge.js";
import { WitnessCalculator } from "./witness-calculator.js";
import { Prover } from "./prover.js";
import { Verifier } from "./verifier.js";
import { jwtParamsForVcSize, preparedMultiKeySetId } from "./multi-circuit.js";
import type {
  OpenACConfig,
  ProofRequest,
  ProofResult,
  VerificationResult,
  VerifyingKeys,
  KeySet,
  PreparedMultiKeySet,
  SerializedKeySet,
  SerializedPreparedMultiKeySet,
  SerializedProof,
  PrecomputeRequest,
  PrecomputePreparedMultiRequest,
  PrecomputedCredential,
  PreparedMultiCredential,
  PreparedMultiShowProof,
  PreparedMultiShowRequest,
  PreparedMultiPresentationProof,
  PreparedMultiPresentationRequest,
  PreparedMultiVerifyingKeys,
  PreparedMultiVerificationOptions,
  PresentRequest,
  PresentationProof,
  JwtCircuitParams,
} from "./types.js";

export class OpenAC {
  private bridge: WasmBridge;
  private prover: Prover;
  private verifier: Verifier;
  private config: OpenACConfig;

  private constructor(
    bridge: WasmBridge,
    prover: Prover,
    verifier: Verifier,
    config: OpenACConfig,
  ) {
    this.bridge = bridge;
    this.prover = prover;
    this.verifier = verifier;
    this.config = config;
  }

  static async init(config: OpenACConfig = {}): Promise<OpenAC> {
    const bridge = new WasmBridge();

    if (config.wasmModule) {
      if (typeof config.wasmModule.default === "function") {
        await config.wasmModule.default();
      }
      bridge.initWithModule(config.wasmModule);
    } else {
      await bridge.init(config.wasmPath);
    }

    // Initialize WitnessCalculator if assetsDir is provided or use default
    let witnessCalculator: WitnessCalculator | undefined;
    try {
      witnessCalculator = new WitnessCalculator(config.assetsDir);
      await witnessCalculator.init();
    } catch {
      // WitnessCalculator initialization is optional - may fail if assets not available
      witnessCalculator = undefined;
    }

    const prover = new Prover(bridge, witnessCalculator);
    const verifier = new Verifier(bridge);

    return new OpenAC(bridge, prover, verifier, config);
  }

  async loadKeysFromUrl(baseUrl: string, vcSize: VcSize): Promise<KeySet> {
    const keys = await this.bridge.loadKeys(baseUrl, vcSize);
    return createKeySet(
      keys.preparePk,
      keys.prepareVk,
      keys.showPk,
      keys.showVk,
      jwtParamsForVcSize(vcSize),
    );
  }

  async loadPreparedMultiKeysFromUrl(
    baseUrl: string,
    vcSize: VcSize,
    credentialCount: number,
  ): Promise<PreparedMultiKeySet> {
    const keys = await this.bridge.loadPreparedMultiKeys(
      baseUrl,
      vcSize,
      credentialCount,
    );
    return createPreparedMultiKeySet(
      keys.preparePk,
      keys.prepareVk,
      keys.showPk,
      keys.showVk,
      keys.linkPk,
      keys.linkVk,
      jwtParamsForVcSize(vcSize),
      credentialCount,
      preparedMultiKeySetId(vcSize, credentialCount),
    );
  }

  async loadKeys(data: SerializedKeySet): Promise<KeySet> {
    return createKeySet(
      data.prepareProvingKey,
      data.prepareVerifyingKey,
      data.showProvingKey,
      data.showVerifyingKey,
      data.jwtParams,
    );
  }

  async loadPreparedMultiKeys(
    data: SerializedPreparedMultiKeySet,
  ): Promise<PreparedMultiKeySet> {
    return createPreparedMultiKeySet(
      data.prepareProvingKey,
      data.prepareVerifyingKey,
      data.showProvingKey,
      data.showVerifyingKey,
      data.linkProvingKey,
      data.linkVerifyingKey,
      data.jwtParams,
      data.credentialCount,
      data.keySetId,
    );
  }

  async precompute(request: PrecomputeRequest): Promise<PrecomputedCredential> {
    return this.prover.precompute(request);
  }

  async precomputePreparedMulti(
    request: PrecomputePreparedMultiRequest,
  ): Promise<PreparedMultiCredential> {
    return this.prover.precomputePreparedMulti(request);
  }

  bundlePrecomputedCredentials(
    precomputedCredentials: PrecomputedCredential[],
  ): PreparedMultiCredential {
    return this.prover.bundlePrecomputedCredentials(precomputedCredentials);
  }

  async precomputePreparedMultiShow(
    request: PreparedMultiShowRequest,
  ): Promise<PreparedMultiShowProof> {
    return this.prover.precomputePreparedMultiShow(request);
  }

  async presentPreparedMulti(
    request: PreparedMultiPresentationRequest,
  ): Promise<PreparedMultiPresentationProof> {
    return this.prover.presentPreparedMulti(request);
  }

  async present(request: PresentRequest): Promise<PresentationProof> {
    return this.prover.present(request);
  }

  async verify(
    proof: PresentationProof,
    keys: VerifyingKeys,
  ): Promise<VerificationResult> {
    return this.verifier.verifyComponents(
      proof.prepareProof,
      proof.showProof,
      keys,
      proof.prepareInstance,
      proof.showInstance,
    );
  }

  async verifyPreparedMulti(
    proof: PreparedMultiPresentationProof,
    keys: PreparedMultiVerifyingKeys,
    expected: PreparedMultiVerificationOptions,
  ): Promise<VerificationResult> {
    return this.verifier.verifyPreparedMulti(proof, keys, expected);
  }

  async createProof(request: ProofRequest): Promise<ProofResult> {
    return this.prover.createProof(request);
  }

  async verifyProof(
    proof: SerializedProof,
    keys: VerifyingKeys,
  ): Promise<VerificationResult> {
    return this.verifier.verifyProof(proof, keys);
  }

  async verifyComponents(
    prepareProof: Uint8Array,
    showProof: Uint8Array,
    keys: VerifyingKeys,
    prepareInstance: Uint8Array,
    showInstance: Uint8Array,
  ): Promise<VerificationResult> {
    return this.verifier.verifyComponents(
      prepareProof,
      showProof,
      keys,
      prepareInstance,
      showInstance,
    );
  }

  get isReady(): boolean {
    return this.bridge.isInitialized;
  }
}

function createKeySet(
  prepareProvingKey: Uint8Array,
  prepareVerifyingKey: Uint8Array,
  showProvingKey: Uint8Array,
  showVerifyingKey: Uint8Array,
  jwtParams?: JwtCircuitParams,
): KeySet {
  return {
    prepareProvingKey,
    prepareVerifyingKey,
    showProvingKey,
    showVerifyingKey,
    jwtParams,

    verifyingKeys(): VerifyingKeys {
      return { prepareVerifyingKey, showVerifyingKey };
    },

    serialize(): SerializedKeySet {
      return {
        prepareProvingKey,
        prepareVerifyingKey,
        showProvingKey,
        showVerifyingKey,
        jwtParams,
      };
    },
  };
}

function createPreparedMultiKeySet(
  prepareProvingKey: Uint8Array,
  prepareVerifyingKey: Uint8Array,
  showProvingKey: Uint8Array,
  showVerifyingKey: Uint8Array,
  linkProvingKey: Uint8Array,
  linkVerifyingKey: Uint8Array,
  jwtParams?: JwtCircuitParams,
  credentialCount?: number,
  keySetId?: string,
): PreparedMultiKeySet {
  return {
    prepareProvingKey,
    prepareVerifyingKey,
    showProvingKey,
    showVerifyingKey,
    linkProvingKey,
    linkVerifyingKey,
    jwtParams,
    credentialCount,
    keySetId,

    verifyingKeys(): VerifyingKeys {
      return { prepareVerifyingKey, showVerifyingKey };
    },

    preparedMultiVerifyingKeys(): PreparedMultiVerifyingKeys {
      return {
        prepareVerifyingKey,
        showVerifyingKey,
        linkVerifyingKey,
        credentialCount,
        keySetId,
      };
    },

    serialize() {
      return {
        prepareProvingKey,
        prepareVerifyingKey,
        showProvingKey,
        showVerifyingKey,
        linkProvingKey,
        linkVerifyingKey,
        jwtParams,
        credentialCount,
        keySetId,
      };
    },
  };
}

// Re-exports
export { Credential } from "./credential.js";
export {
  Prover,
  deserializePrecomputed,
  deserializePreparedMulti,
  deserializePreparedMultiPresentation,
  bundlePrecomputedCredentials,
} from "./prover.js";
export { Verifier } from "./verifier.js";
export { WitnessCalculator } from "./witness-calculator.js";
export { NativeBackend } from "./native-backend.js";
export type { NativeBackendConfig } from "./native-backend.js";
export { buildJwtCircuitInputs } from "./inputs/jwt-input-builder.js";
export {
  buildShowCircuitInputs,
  buildShowPolicyPublicInputs,
  buildShowPolicyPublicValues,
  buildPreparedMultiVerifierNonce,
  signDeviceNonce,
  PredicateOp,
  LogicToken,
} from "./inputs/show-input-builder.js";
export type {
  ShowInputOptions,
  PredicateSpec,
  ShowPolicyPublicInputs,
} from "./inputs/show-input-builder.js";

export {
  OpenACError,
  SetupError,
  ProofError,
  VerificationError,
  InputError,
  WasmError,
} from "./errors.js";

export type {
  OpenACConfig,
  ProofRequest,
  ProofResult,
  ProofTiming,
  ProofPublicValues,
  VerificationResult,
  VerifyingKeys,
  KeySet,
  PreparedMultiKeySet,
  SerializedKeySet,
  SerializedPreparedMultiKeySet,
  SerializedProof,
  SerializedProofJSON,
  SerializedPreparedMultiPresentationProofJSON,
  DisclosedClaim,
  EcdsaPublicKey,
  EcdsaPrivateKey,
  IssuerPublicKey,
  PemPublicKey,
  JwtCircuitParams,
  ShowCircuitParams,
  JwtCircuitInputs,
  ShowCircuitInputs,
  MultiCredentialCircuitKind,
  CircuitArtifacts,
  ErrorCode,
  PrecomputeRequest,
  PrecomputePreparedMultiRequest,
  PrecomputedCredential,
  PreparedMultiCredential,
  PreparedMultiShowProof,
  PreparedMultiShowRequest,
  PreparedMultiPresentationProof,
  PreparedMultiPresentationRequest,
  PreparedMultiVerifyingKeys,
  PreparedMultiVerificationOptions,
  PreparedMultiChallengeRequest,
  PrecomputeTiming,
  PresentRequest,
  PresentationProof,
  PresentationTiming,
  PreparedMultiShowTiming,
  MultiCredentialInput,
  ClaimNamespaceEntry,
  SerializedCredential,
  SerializedPrecomputedCredentialJSON,
  SerializedPreparedMultiCredentialJSON,
} from "./types.js";

export {
  SUPPORTED_PREPARED_MULTI_CREDENTIAL_COUNTS,
  getPreparedMultiShowCircuitProfile,
  preparedMultiKeyFilenames,
  preparedMultiKeySetId,
  preparedMultiShowKeyFilenames,
  jwtParamsForVcSize,
} from "./multi-circuit.js";

export {
  base64urlToBase64,
  base64ToBase64url,
  base64Decode,
  base64Encode,
  base64urlEncode,
  base64ToBigInt,
  base64urlToBigInt,
  bigintToBase64url,
  bytesToBigInt,
  bigintToBytes,
  uint8ArrayToBigIntArray,
  stringToPaddedBigIntArray,
  sha256Pad,
  sha256Hash,
  sha256HashString,
  encodeClaims,
  modInverse,
  modScalarField,
  circuitInputsToJson,
  jwkPointToBigInt,
  P256_SCALAR_ORDER,
} from "./utils.js";

export {
  DEFAULT_JWT_PARAMS,
  DEFAULT_JWT_1K_PARAMS,
  DEFAULT_SHOW_PARAMS,
  DEFAULT_SHOW_2VC_PARAMS,
} from "./types.js";

import { WasmBridge, VcSize } from "./wasm-bridge.js";
import { WitnessCalculator } from "./witness-calculator.js";
import { Prover } from "./prover.js";
import { Verifier } from "./verifier.js";
import type {
  OpenACConfig,
  ProofRequest,
  ProofResult,
  VerificationResult,
  VerifyingKeys,
  KeySet,
  PreparedMultiKeySet,
  SerializedKeySet,
  SerializedProof,
  PrecomputeRequest,
  PrecomputeMultiRequest,
  PrecomputePreparedMultiRequest,
  PrecomputedCredential,
  PreparedMultiCredential,
  PreparedMultiShowProof,
  PreparedMultiShowRequest,
  PreparedMultiPresentationProof,
  PreparedMultiPresentationRequest,
  PreparedMultiVerifyingKeys,
  PrecomputedMultiCredential,
  PresentRequest,
  PresentMultiRequest,
  PresentationProof,
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
    );
  }

  async loadMultiKeysFromUrl(
    baseUrl: string,
    vcSize: VcSize,
    credentialCount = 2,
  ): Promise<KeySet> {
    const keys = await this.bridge.loadMultiKeys(
      baseUrl,
      vcSize,
      credentialCount,
    );
    return createKeySet(
      keys.preparePk,
      keys.prepareVk,
      keys.showPk,
      keys.showVk,
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
    );
  }

  async loadKeys(data: SerializedKeySet): Promise<KeySet> {
    return createKeySet(
      data.prepareProvingKey,
      data.prepareVerifyingKey,
      data.showProvingKey,
      data.showVerifyingKey,
    );
  }

  async precompute(request: PrecomputeRequest): Promise<PrecomputedCredential> {
    return this.prover.precompute(request);
  }

  async precomputeMulti(
    request: PrecomputeMultiRequest,
  ): Promise<PrecomputedMultiCredential> {
    return this.prover.precomputeMulti(request);
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

  async presentMulti(request: PresentMultiRequest): Promise<PresentationProof> {
    return this.prover.presentMulti(request);
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
  ): Promise<VerificationResult> {
    return this.verifier.verifyPreparedMulti(proof, keys);
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
): KeySet {
  return {
    prepareProvingKey,
    prepareVerifyingKey,
    showProvingKey,
    showVerifyingKey,

    verifyingKeys(): VerifyingKeys {
      return { prepareVerifyingKey, showVerifyingKey };
    },

    serialize(): SerializedKeySet {
      return {
        prepareProvingKey,
        prepareVerifyingKey,
        showProvingKey,
        showVerifyingKey,
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
): PreparedMultiKeySet {
  return {
    prepareProvingKey,
    prepareVerifyingKey,
    showProvingKey,
    showVerifyingKey,
    linkProvingKey,
    linkVerifyingKey,

    verifyingKeys(): VerifyingKeys {
      return { prepareVerifyingKey, showVerifyingKey };
    },

    preparedMultiVerifyingKeys(): PreparedMultiVerifyingKeys {
      return { prepareVerifyingKey, showVerifyingKey, linkVerifyingKey };
    },

    serialize() {
      return {
        prepareProvingKey,
        prepareVerifyingKey,
        showProvingKey,
        showVerifyingKey,
        linkProvingKey,
        linkVerifyingKey,
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
  deserializePrecomputedMulti,
  bundlePrecomputedCredentials,
} from "./prover.js";
export { Verifier } from "./verifier.js";
export { WitnessCalculator } from "./witness-calculator.js";
export { NativeBackend } from "./native-backend.js";
export type { NativeBackendConfig } from "./native-backend.js";
export {
  buildJwtCircuitInputs,
  buildPrepare2VcCircuitInputs,
  buildPrepareMultiVcCircuitInputs,
} from "./inputs/jwt-input-builder.js";
export {
  buildShowCircuitInputs,
  signDeviceNonce,
  PredicateOp,
  LogicToken,
} from "./inputs/show-input-builder.js";
export type { ShowInputOptions, PredicateSpec } from "./inputs/show-input-builder.js";

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
  DisclosedClaim,
  EcdsaPublicKey,
  EcdsaPrivateKey,
  IssuerPublicKey,
  PemPublicKey,
  JwtCircuitParams,
  ShowCircuitParams,
  JwtCircuitInputs,
  Prepare2VcCircuitInputs,
  PrepareMultiVcCircuitInputs,
  ShowCircuitInputs,
  MultiCredentialCircuitKind,
  CircuitArtifacts,
  ErrorCode,
  PrecomputeRequest,
  PrecomputeMultiRequest,
  PrecomputePreparedMultiRequest,
  PrecomputedCredential,
  PreparedMultiCredential,
  PreparedMultiShowProof,
  PreparedMultiShowRequest,
  PreparedMultiPresentationProof,
  PreparedMultiPresentationRequest,
  PreparedMultiVerifyingKeys,
  PrecomputedMultiCredential,
  PrecomputeTiming,
  PresentRequest,
  PresentMultiRequest,
  PresentationProof,
  PresentationTiming,
  PreparedMultiShowTiming,
  MultiCredentialInput,
  ClaimNamespaceEntry,
  SerializedCredential,
  SerializedPrecomputedCredentialJSON,
  SerializedPreparedMultiCredentialJSON,
  SerializedPrecomputedMultiCredentialJSON,
} from "./types.js";

export {
  SUPPORTED_PREPARED_MULTI_CREDENTIAL_COUNTS,
  SUPPORTED_MULTI_CREDENTIAL_COUNTS,
  getPreparedMultiShowCircuitProfile,
  getMultiCredentialCircuitProfile,
  multiCredentialKeyFilenames,
  preparedMultiKeyFilenames,
  preparedMultiShowKeyFilenames,
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

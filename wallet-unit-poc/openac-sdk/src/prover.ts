// Orchestrates the full Prepare -> Show proving pipeline.

import { WasmBridge } from "./wasm-bridge.js";
import { WitnessCalculator } from "./witness-calculator.js";
import { Credential } from "./credential.js";
import { buildJwtCircuitInputs } from "./inputs/jwt-input-builder.js";
import {
  buildShowCircuitInputs,
  signDeviceNonce,
} from "./inputs/show-input-builder.js";
import {
  getMultiCredentialCircuitProfile,
  getPreparedMultiShowCircuitProfile,
} from "./multi-circuit.js";
import { circuitInputsToJson, base64Encode } from "./utils.js";
import { InputError, ProofError } from "./errors.js";
import { base64Decode } from "./utils.js";
import {
  DEFAULT_JWT_PARAMS,
  DEFAULT_SHOW_PARAMS,
} from "./types.js";
import type {
  ProofRequest,
  ProofResult,
  ProofPublicValues,
  ProofTiming,
  SerializedProofJSON,
  JwtCircuitParams,
  ShowCircuitParams,
  PrecomputeRequest,
  PrecomputeMultiRequest,
  PrecomputePreparedMultiRequest,
  PrecomputedCredential,
  PreparedMultiCredential,
  PreparedMultiShowProof,
  PreparedMultiShowRequest,
  PrecomputedMultiCredential,
  PrecomputeTiming,
  PresentRequest,
  PresentMultiRequest,
  PresentationProof,
  PresentationTiming,
  SerializedPrecomputedCredentialJSON,
  SerializedPreparedMultiCredentialJSON,
  SerializedPrecomputedMultiCredentialJSON,
  EcdsaPublicKey,
  MultiCredentialInput,
  ClaimNamespaceEntry,
  MultiCredentialCircuitKind,
} from "./types.js";

const SDK_VERSION = "0.1.0";

export class Prover {
  private bridge: WasmBridge;
  private witnessCalculator: WitnessCalculator | null = null;

  constructor(bridge: WasmBridge, witnessCalculator?: WitnessCalculator) {
    this.bridge = bridge;
    this.witnessCalculator = witnessCalculator ?? null;
  }

  async initWitnessCalculator(assetsDir?: string): Promise<void> {
    this.witnessCalculator = new WitnessCalculator(assetsDir);
    await this.witnessCalculator.init();
  }

  get hasWitnessCalculator(): boolean {
    return this.witnessCalculator !== null;
  }

  async precompute(request: PrecomputeRequest): Promise<PrecomputedCredential> {
    const startTime = performance.now();
    const timing: Partial<PrecomputeTiming> = {};

    let t1 = performance.now();
    const credential = Credential.parse(request.jwt, request.disclosures);
    timing.parseCredentialMs = performance.now() - t1;

    const autoDetectedBirthday = credential.findBirthdayClaim();
    const birthdayClaimIndex =
      request.birthdayClaimIndex ?? autoDetectedBirthday ?? -1;
    const birthdayClaim = birthdayClaimIndex >= 0
      ? credential.claims[birthdayClaimIndex]
      : undefined;
    if (request.birthdayClaimIndex !== undefined && !birthdayClaim) {
      throw new InputError(
        "BIRTHDAY_NOT_FOUND",
        `No claim at index ${birthdayClaimIndex}`,
      );
    }

    const deviceKey = credential.deviceBindingKey;
    if (!deviceKey) {
      throw new InputError(
        "INVALID_JWT",
        "JWT payload does not contain device binding key (cnf.jwk)",
      );
    }

    t1 = performance.now();
    const decodeFlags = request.decodeFlags ?? this.defaultDecodeFlags(credential);
    const additionalMatches =
      request.additionalMatches ?? credential.disclosureHashes;
    const jwtParams: JwtCircuitParams = request.jwtParams ?? DEFAULT_JWT_PARAMS;

    const claimFormats = request.claimFormats ?? this.defaultClaimFormats(credential);

    const jwtInputs = buildJwtCircuitInputs(
      credential,
      request.issuerPublicKey,
      jwtParams,
      additionalMatches,
      decodeFlags,
      claimFormats,
    );
    const jwtInputsJson = circuitInputsToJson(jwtInputs);
    timing.buildInputsMs = performance.now() - t1;

    t1 = performance.now();
    const prepareWitnessBytes = await this.generatePrepareWitness(jwtInputsJson);
    timing.prepareWitnessMs = performance.now() - t1;

    t1 = performance.now();
    const prepareResult = await this.bridge.precomputeFromWitness(
      request.keys.prepareProvingKey,
      prepareWitnessBytes,
    );
    timing.prepareProveMs = performance.now() - t1;
    timing.totalMs = performance.now() - startTime;

    const prepareWitness = await this.calculateJwtWitness(jwtInputsJson);
    const claimsPerCredential = jwtParams.maxMatches - 2;
    const normalizedClaimValues = prepareWitness.slice(
      1,
      1 + claimsPerCredential,
    );

    return this.buildPrecomputedCredential(
      prepareResult.proof,
      prepareResult.instance,
      prepareResult.witness,
      credential,
      birthdayClaimIndex,
      birthdayClaim?.raw ?? "",
      deviceKey,
      claimsPerCredential,
      normalizedClaimValues,
      this.buildClaimNamespace([credential], claimsPerCredential),
      timing as PrecomputeTiming,
    );
  }

  async precomputeMulti(
    request: PrecomputeMultiRequest,
  ): Promise<PrecomputedMultiCredential> {
    const startTime = performance.now();
    const timing: Partial<PrecomputeTiming> = {};
    const credentialCount = request.credentialCount ?? request.credentials.length;
    const profile = getMultiCredentialCircuitProfile(credentialCount);
    const jwtParams: JwtCircuitParams = request.jwtParams ?? profile.defaultJwtParams;
    if (request.credentials.length !== profile.credentialCount) {
      throw new InputError(
        "PARAMS_EXCEEDED",
        `precomputeMulti for ${profile.kind} requires exactly ${profile.credentialCount} credentials`,
      );
    }

    let t1 = performance.now();
    const credentials = request.credentials.map((input) =>
      Credential.parse(input.jwt, input.disclosures),
    );
    timing.parseCredentialMs = performance.now() - t1;

    const deviceKey = this.requireDeviceKey(credentials[0]!);
    for (const credential of credentials.slice(1)) {
      this.assertSameDeviceKey(deviceKey, this.requireDeviceKey(credential));
    }

    t1 = performance.now();
    const jwtInputs = credentials.map((credential, index) =>
      this.buildJwtInputsForMultiCredential(
        credential,
        request.credentials[index]!,
        jwtParams,
      ),
    );
    const prepareInputs = profile.buildPrepareInputs(jwtInputs);
    const prepareInputsJson = circuitInputsToJson(prepareInputs);
    timing.buildInputsMs = performance.now() - t1;

    t1 = performance.now();
    const prepareWitnessBytes = await this.generatePrepareMultiWitness(
      profile.credentialCount,
      prepareInputsJson,
    );
    timing.prepareWitnessMs = performance.now() - t1;

    t1 = performance.now();
    const prepareResult = await this.bridge.precomputePrepareMultiFromWitness(
      profile.credentialCount,
      request.keys.prepareProvingKey,
      prepareWitnessBytes,
    );
    timing.prepareProveMs = performance.now() - t1;

    const prepareWitness = await this.calculatePrepareMultiWitness(
      profile.credentialCount,
      prepareInputsJson,
    );
    const claimsPerCredential = jwtParams.maxMatches - 2;
    const normalizedClaimValues = prepareWitness.slice(
      1,
      1 + claimsPerCredential * profile.credentialCount,
    );
    const claimNamespace = this.buildClaimNamespace(
      credentials,
      claimsPerCredential,
    );

    timing.totalMs = performance.now() - startTime;

    return this.buildPrecomputedMultiCredential(
      prepareResult.proof,
      prepareResult.instance,
      prepareResult.witness,
      credentials,
      profile.kind,
      deviceKey,
      claimsPerCredential,
      normalizedClaimValues,
      claimNamespace,
      timing as PrecomputeTiming,
    );
  }

  async precomputePreparedMulti(
    request: PrecomputePreparedMultiRequest,
  ): Promise<PreparedMultiCredential> {
    const prepared: PrecomputedCredential[] = [];
    for (const credential of request.credentials) {
      prepared.push(
        await this.precompute({
          jwt: credential.jwt,
          disclosures: credential.disclosures,
          issuerPublicKey: credential.issuerPublicKey,
          keys: request.keys,
          jwtParams: request.jwtParams,
          decodeFlags: credential.decodeFlags,
          claimFormats: credential.claimFormats,
          additionalMatches: credential.additionalMatches,
        }),
      );
    }
    return this.bundlePrecomputedCredentials(prepared);
  }

  bundlePrecomputedCredentials(
    precomputedCredentials: PrecomputedCredential[],
  ): PreparedMultiCredential {
    return bundlePrecomputedCredentials(precomputedCredentials);
  }

  async precomputePreparedMultiShow(
    request: PreparedMultiShowRequest,
  ): Promise<PreparedMultiShowProof> {
    const startTime = performance.now();
    const timing: Partial<PresentationTiming> = {};

    const { prepared, verifierNonce, devicePrivateKey, keys } = request;
    const profile = getPreparedMultiShowCircuitProfile(prepared.credentialCount);
    if (prepared.kind !== profile.kind) {
      throw new InputError(
        "PARAMS_EXCEEDED",
        `Prepared bundle kind ${prepared.kind} does not match ${profile.kind}`,
      );
    }

    const showParams = request.showParams ?? profile.defaultShowParams;
    if (showParams.nClaims !== prepared.normalizedClaimValues.length) {
      throw new InputError(
        "PARAMS_EXCEEDED",
        `showParams.nClaims (${showParams.nClaims}) must match prepared normalized claim count (${prepared.normalizedClaimValues.length})`,
      );
    }

    const suppliedClaimValues = request.showInputOptions?.normalizedClaimValues;
    if (
      suppliedClaimValues &&
      !this.bigintArraysEqual(suppliedClaimValues, prepared.normalizedClaimValues)
    ) {
      throw new InputError(
        "PARAMS_EXCEEDED",
        "showInputOptions.normalizedClaimValues must match the prepared normalized claims",
      );
    }

    const deviceSignature = signDeviceNonce(verifierNonce, devicePrivateKey);
    const showInputs = buildShowCircuitInputs(
      showParams,
      verifierNonce,
      deviceSignature,
      prepared.deviceKey,
      {
        ...request.showInputOptions,
        normalizedClaimValues: prepared.normalizedClaimValues,
      },
    );
    const showInputsJson = circuitInputsToJson(showInputs);

    let t1 = performance.now();
    const showWitnessBytes = await this.generateShowMultiWitness(
      profile.credentialCount,
      showInputsJson,
    );
    timing.showWitnessMs = performance.now() - t1;

    t1 = performance.now();
    const showResult = await this.bridge.precomputeShowMultiFromWitness(
      profile.credentialCount,
      keys.showProvingKey,
      showWitnessBytes,
    );
    timing.showProveMs = performance.now() - t1;
    timing.totalMs = performance.now() - startTime;

    const showWitness = await this.calculateShowMultiWitness(
      profile.credentialCount,
      showInputsJson,
    );
    const publicValues: ProofPublicValues = {
      expressionResult: showWitness[1] === 1n,
      deviceKeyX: showInputs.deviceKeyX.toString(),
      deviceKeyY: showInputs.deviceKeyY.toString(),
      normalizedClaimValues: prepared.normalizedClaimValues,
    };

    return {
      kind: profile.kind,
      credentialCount: profile.credentialCount,
      showProof: showResult.proof,
      showInstance: showResult.instance,
      showWitness: showResult.witness,
      publicValues,
      timing: {
        showWitnessMs: timing.showWitnessMs ?? 0,
        showProveMs: timing.showProveMs ?? 0,
        totalMs: timing.totalMs ?? 0,
      },
    };
  }

  async present(request: PresentRequest): Promise<PresentationProof> {
    const startTime = performance.now();
    const timing: Partial<PresentationTiming> = {};

    const { precomputed, verifierNonce, devicePrivateKey, keys } = request;
    const showParams = request.showParams ?? DEFAULT_SHOW_PARAMS;
    if (showParams.nClaims !== precomputed.normalizedClaimValues.length) {
      throw new InputError(
        "PARAMS_EXCEEDED",
        `showParams.nClaims (${showParams.nClaims}) must match precomputed normalized claim count (${precomputed.normalizedClaimValues.length})`,
      );
    }
    const suppliedClaimValues = request.showInputOptions?.normalizedClaimValues;
    if (
      suppliedClaimValues &&
      !this.bigintArraysEqual(suppliedClaimValues, precomputed.normalizedClaimValues)
    ) {
      throw new InputError(
        "PARAMS_EXCEEDED",
        "showInputOptions.normalizedClaimValues must match the precomputed Prepare outputs",
      );
    }

    const deviceSignature = signDeviceNonce(verifierNonce, devicePrivateKey);

    const showInputs = buildShowCircuitInputs(
      showParams,
      verifierNonce,
      deviceSignature,
      precomputed.deviceKey,
      {
        ...request.showInputOptions,
        normalizedClaimValues: precomputed.normalizedClaimValues,
      },
    );
    const showInputsJson = circuitInputsToJson(showInputs);

    let t1 = performance.now();
    const showWitnessBytes = await this.generateShowWitness(showInputsJson);
    timing.showWitnessMs = performance.now() - t1;

    t1 = performance.now();
    const showResult = await this.bridge.precomputeShowFromWitness(
      keys.showProvingKey,
      showWitnessBytes,
    );
    timing.showProveMs = performance.now() - t1;

    t1 = performance.now();
    const presentResult = await this.bridge.present(
      keys.prepareProvingKey,
      precomputed.prepareInstance,
      precomputed.prepareWitness,
      keys.showProvingKey,
      showResult.instance,
      showResult.witness,
    );
    timing.presentMs = performance.now() - t1;
    timing.totalMs = performance.now() - startTime;

    let expressionResult = false;
    if (this.witnessCalculator) {
      const inputs = this.parseJsonToBigInt(showInputsJson);
      const showWitness = await this.witnessCalculator.calculateShowWitness(inputs);
      expressionResult = showWitness[1] === 1n;
    }

    const publicValues: ProofPublicValues = {
      expressionResult,
      deviceKeyX: showInputs.deviceKeyX.toString(),
      deviceKeyY: showInputs.deviceKeyY.toString(),
      normalizedClaimValues: precomputed.normalizedClaimValues,
    };

    return this.buildPresentationProof(
      presentResult.prepareProof,
      presentResult.prepareInstance,
      presentResult.showProof,
      presentResult.showInstance,
      publicValues,
      timing as PresentationTiming,
    );
  }

  async presentMulti(request: PresentMultiRequest): Promise<PresentationProof> {
    const startTime = performance.now();
    const timing: Partial<PresentationTiming> = {};

    const { precomputed, verifierNonce, devicePrivateKey, keys } = request;
    const profile = getMultiCredentialCircuitProfile(precomputed.credentialCount);
    const showParams = request.showParams ?? profile.defaultShowParams;
    if (showParams.nClaims !== precomputed.normalizedClaimValues.length) {
      throw new InputError(
        "PARAMS_EXCEEDED",
        `showParams.nClaims (${showParams.nClaims}) must match precomputed normalized claim count (${precomputed.normalizedClaimValues.length})`,
      );
    }

    const suppliedClaimValues = request.showInputOptions?.normalizedClaimValues;
    if (
      suppliedClaimValues &&
      !this.bigintArraysEqual(suppliedClaimValues, precomputed.normalizedClaimValues)
    ) {
      throw new InputError(
        "PARAMS_EXCEEDED",
        "showInputOptions.normalizedClaimValues must match the precomputed Prepare outputs",
      );
    }

    const deviceSignature = signDeviceNonce(verifierNonce, devicePrivateKey);
    const showInputs = buildShowCircuitInputs(
      showParams,
      verifierNonce,
      deviceSignature,
      precomputed.deviceKey,
      {
        ...request.showInputOptions,
        normalizedClaimValues: precomputed.normalizedClaimValues,
      },
    );
    const showInputsJson = circuitInputsToJson(showInputs);

    let t1 = performance.now();
    const showWitnessBytes = await this.generateShowMultiWitness(
      profile.credentialCount,
      showInputsJson,
    );
    timing.showWitnessMs = performance.now() - t1;

    t1 = performance.now();
    const showResult = await this.bridge.precomputeShowMultiFromWitness(
      profile.credentialCount,
      keys.showProvingKey,
      showWitnessBytes,
    );
    timing.showProveMs = performance.now() - t1;

    t1 = performance.now();
    const presentResult = await this.bridge.present(
      keys.prepareProvingKey,
      precomputed.prepareInstance,
      precomputed.prepareWitness,
      keys.showProvingKey,
      showResult.instance,
      showResult.witness,
    );
    timing.presentMs = performance.now() - t1;
    timing.totalMs = performance.now() - startTime;

    const showWitness = await this.calculateShowMultiWitness(
      profile.credentialCount,
      showInputsJson,
    );
    const publicValues: ProofPublicValues = {
      expressionResult: showWitness[1] === 1n,
      deviceKeyX: showInputs.deviceKeyX.toString(),
      deviceKeyY: showInputs.deviceKeyY.toString(),
      normalizedClaimValues: precomputed.normalizedClaimValues,
    };

    return this.buildPresentationProof(
      presentResult.prepareProof,
      presentResult.prepareInstance,
      presentResult.showProof,
      presentResult.showInstance,
      publicValues,
      timing as PresentationTiming,
    );
  }

  async createProof(request: ProofRequest): Promise<ProofResult> {
    const startTime = performance.now();
    const timing: Partial<ProofTiming> = {};

    const credential = Credential.parse(request.jwt, request.disclosures);

    // determine birthday claim index
    let birthdayClaimIndex: number;
    if (request.birthdayClaimIndex !== undefined) {
      birthdayClaimIndex = request.birthdayClaimIndex;
    } else {
      const autoDetected = credential.findBirthdayClaim();
      if (autoDetected === null) {
        throw new InputError(
          "BIRTHDAY_NOT_FOUND",
          "Could not auto-detect birthday claim. Provide birthdayClaimIndex explicitly.",
        );
      }
      birthdayClaimIndex = autoDetected;
    }

    const decodeFlags =
      request.decodeFlags ??
      credential.claims.map((_, i) => (i === birthdayClaimIndex ? 1 : 0));

    const additionalMatches =
      request.additionalMatches ?? credential.disclosureHashes;

    const jwtParams: JwtCircuitParams = request.jwtParams ?? {
      maxMessageLength: 1920,
      maxB64PayloadLength: 1900,
      maxMatches: 4,
      maxSubstringLength: 50,
      maxClaimLength: 128,
    };

    const showParams: ShowCircuitParams = request.showParams ?? DEFAULT_SHOW_PARAMS;

    const claimFormats = credential.claims.map((_, i) => (i === birthdayClaimIndex ? 3 : 4));

    const jwtInputs = buildJwtCircuitInputs(
      credential,
      request.issuerPublicKey,
      jwtParams,
      additionalMatches,
      decodeFlags,
      claimFormats,
    );

    const jwtInputsJson = circuitInputsToJson(jwtInputs);

    const keys = request.keys;
    if (!keys) {
      throw new ProofError(
        "PROOF_GENERATION_FAILED",
        "Keys are required. Call setup() first or provide keys in ProofRequest.",
      );
    }

    let t1 = performance.now();
    const prepareWitnessBytes = await this.generatePrepareWitness(jwtInputsJson);
    const prepareResult = await this.bridge.precomputeFromWitness(keys.prepareProvingKey, prepareWitnessBytes);
    timing.prepareProveMs = performance.now() - t1;

    // build Show circuit inputs
    const deviceSignature = signDeviceNonce(
      request.verifierNonce,
      request.devicePrivateKey,
    );

    const deviceKey = credential.deviceBindingKey;
    if (!deviceKey) {
      throw new InputError(
        "INVALID_JWT",
        "JWT payload does not contain device binding key (cnf.jwk)",
      );
    }

    const showInputs = buildShowCircuitInputs(
      showParams,
      request.verifierNonce,
      deviceSignature,
      deviceKey,
    );

    const showInputsJson = circuitInputsToJson(showInputs);

    t1 = performance.now();
    const showWitnessBytes = await this.generateShowWitness(showInputsJson);
    const showResult = await this.bridge.precomputeShowFromWitness(keys.showProvingKey, showWitnessBytes);
    timing.showProveMs = performance.now() - t1;

    t1 = performance.now();
    const presentResult = await this.bridge.present(
      keys.prepareProvingKey,
      prepareResult.instance,
      prepareResult.witness,
      keys.showProvingKey,
      showResult.instance,
      showResult.witness,
    );
    timing.prepareReblindMs = performance.now() - t1;
    timing.showReblindMs = 0; // Included in the present() call above

    timing.totalMs = performance.now() - startTime;

    // Extract expressionResult and normalizedClaimValues from witness outputs
    // JWT circuit (maxMatches=4): w[1..2] = normalizedClaimValues[0..1], w[3] = KeyBindingX, w[4] = KeyBindingY
    // Show circuit: w[1] = expressionResult (0 or 1), w[2] = deviceKeyX, w[3] = deviceKeyY
    let expressionResult = false;
    let normalizedClaimValues: bigint[] = [];
    const maxClaims = jwtParams.maxMatches - 2;

    if (this.witnessCalculator) {
      const jwtWitness = await this.calculateJwtWitness(jwtInputsJson);
      normalizedClaimValues = jwtWitness.slice(1, 1 + maxClaims);

      const showWitness = await this.calculateShowWitness(showInputsJson);
      expressionResult = showWitness[1] === 1n;
    }

    const publicValues: ProofPublicValues = {
      expressionResult,
      deviceKeyX: showInputs.deviceKeyX.toString(),
      deviceKeyY: showInputs.deviceKeyY.toString(),
      normalizedClaimValues,
    };

    const result: ProofResult = {
      prepareProof: presentResult.prepareProof,
      showProof: presentResult.showProof,
      prepareInstance: presentResult.prepareInstance,
      showInstance: presentResult.showInstance,
      publicValues,
      timing: timing as ProofTiming,

      serialize(): Uint8Array {
        return serializeProofBundle(result);
      },

      toBase64(): string {
        return base64Encode(serializeProofBundle(result));
      },

      toJSON(): SerializedProofJSON {
        return {
          version: SDK_VERSION,
          prepareProof: base64Encode(result.prepareProof),
          showProof: base64Encode(result.showProof),
          prepareInstance: base64Encode(result.prepareInstance),
          showInstance: base64Encode(result.showInstance),
          publicValues: {
            expressionResult: result.publicValues.expressionResult,
            deviceKeyX: result.publicValues.deviceKeyX,
            deviceKeyY: result.publicValues.deviceKeyY,
          },
        };
      },
    };

    return result;
  }

  private async generatePrepareWitness(
    inputsJson: string,
  ): Promise<Uint8Array> {
    if (!this.witnessCalculator) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "WitnessCalculator not initialized. Call initWitnessCalculator() first or provide it in constructor.",
      );
    }
    const inputs = this.parseJsonToBigInt(inputsJson);
    return await this.witnessCalculator.calculateJwtWitnessWtns(inputs);
  }

  private async generateShowWitness(inputsJson: string): Promise<Uint8Array> {
    if (!this.witnessCalculator) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "WitnessCalculator not initialized. Call initWitnessCalculator() first or provide it in constructor.",
      );
    }
    const inputs = this.parseJsonToBigInt(inputsJson);
    return await this.witnessCalculator.calculateShowWitnessWtns(inputs);
  }

  private async generatePrepareMultiWitness(
    credentialCount: number,
    inputsJson: string,
  ): Promise<Uint8Array> {
    if (!this.witnessCalculator) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "WitnessCalculator not initialized. Call initWitnessCalculator() first or provide it in constructor.",
      );
    }
    const inputs = this.parseJsonToBigInt(inputsJson);
    return await this.witnessCalculator.calculatePrepareMultiWitnessWtns(
      credentialCount,
      inputs,
    );
  }

  private async generateShowMultiWitness(
    credentialCount: number,
    inputsJson: string,
  ): Promise<Uint8Array> {
    if (!this.witnessCalculator) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "WitnessCalculator not initialized. Call initWitnessCalculator() first or provide it in constructor.",
      );
    }
    const inputs = this.parseJsonToBigInt(inputsJson);
    return await this.witnessCalculator.calculateShowMultiWitnessWtns(
      credentialCount,
      inputs,
    );
  }

  private async calculateJwtWitness(inputsJson: string): Promise<bigint[]> {
    if (!this.witnessCalculator) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "WitnessCalculator not initialized.",
      );
    }
    const inputs = this.parseJsonToBigInt(inputsJson);
    return await this.witnessCalculator.calculateJwtWitness(inputs);
  }

  private async calculateShowWitness(inputsJson: string): Promise<bigint[]> {
    if (!this.witnessCalculator) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "WitnessCalculator not initialized.",
      );
    }
    const inputs = this.parseJsonToBigInt(inputsJson);
    return await this.witnessCalculator.calculateShowWitness(inputs);
  }

  private async calculatePrepareMultiWitness(
    credentialCount: number,
    inputsJson: string,
  ): Promise<bigint[]> {
    if (!this.witnessCalculator) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "WitnessCalculator not initialized.",
      );
    }
    const inputs = this.parseJsonToBigInt(inputsJson);
    return await this.witnessCalculator.calculatePrepareMultiWitness(
      credentialCount,
      inputs,
    );
  }

  private async calculateShowMultiWitness(
    credentialCount: number,
    inputsJson: string,
  ): Promise<bigint[]> {
    if (!this.witnessCalculator) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "WitnessCalculator not initialized.",
      );
    }
    const inputs = this.parseJsonToBigInt(inputsJson);
    return await this.witnessCalculator.calculateShowMultiWitness(
      credentialCount,
      inputs,
    );
  }

  private parseJsonToBigInt(json: string): Record<string, unknown> {
    return JSON.parse(json, (_key, value) => {
      if (typeof value === "string" && /^-?\d+$/.test(value)) {
        return BigInt(value);
      }
      return value;
    });
  }

  private buildJwtInputsForMultiCredential(
    credential: Credential,
    input: MultiCredentialInput,
    jwtParams: JwtCircuitParams,
  ) {
    return buildJwtCircuitInputs(
      credential,
      input.issuerPublicKey,
      jwtParams,
      input.additionalMatches ?? credential.disclosureHashes,
      input.decodeFlags ?? this.defaultDecodeFlags(credential),
      input.claimFormats ?? this.defaultClaimFormats(credential),
    );
  }

  private defaultDecodeFlags(credential: Credential): number[] {
    return credential.claims.map((claim) =>
      this.isBirthdayClaimName(claim.name) ? 1 : 0,
    );
  }

  private defaultClaimFormats(credential: Credential): number[] {
    return credential.claims.map((claim) => {
      if (this.isBirthdayClaimName(claim.name)) return 3;
      if (/^-?\d+$/.test(claim.value)) return 1;
      return 4;
    });
  }

  private isBirthdayClaimName(name: string): boolean {
    return ["roc_birthday", "birthdate", "birthday", "date_of_birth"].includes(
      name,
    );
  }

  private requireDeviceKey(credential: Credential): EcdsaPublicKey {
    const deviceKey = credential.deviceBindingKey;
    if (!deviceKey) {
      throw new InputError(
        "INVALID_JWT",
        "JWT payload does not contain device binding key (cnf.jwk)",
      );
    }
    return deviceKey;
  }

  private assertSameDeviceKey(
    expected: EcdsaPublicKey,
    actual: EcdsaPublicKey,
  ): void {
    if (expected.x !== actual.x || expected.y !== actual.y) {
      throw new InputError(
        "INVALID_KEY",
        "All credentials in a multi-VC presentation must use the same device binding key",
      );
    }
  }

  private buildClaimNamespace(
    credentials: Credential[],
    claimsPerCredential: number,
  ): ClaimNamespaceEntry[] {
    const entries: ClaimNamespaceEntry[] = [];
    for (let credentialIndex = 0; credentialIndex < credentials.length; credentialIndex++) {
      const credential = credentials[credentialIndex]!;
      for (let claimIndex = 0; claimIndex < claimsPerCredential; claimIndex++) {
        const claim = credential.claims[claimIndex];
        entries.push({
          globalIndex: credentialIndex * claimsPerCredential + claimIndex,
          credentialIndex,
          claimIndex,
          claimName: claim?.name ?? "",
        });
      }
    }
    return entries;
  }

  private bigintArraysEqual(left: bigint[], right: bigint[]): boolean {
    return (
      left.length === right.length &&
      left.every((value, index) => value === right[index])
    );
  }

  private buildPrecomputedCredential(
    prepareProof: Uint8Array,
    prepareInstance: Uint8Array,
    prepareWitness: Uint8Array,
    credential: Credential,
    birthdayClaimIndex: number,
    birthdayClaim: string,
    deviceKey: EcdsaPublicKey,
    claimsPerCredential: number,
    normalizedClaimValues: bigint[],
    claimNamespace: ClaimNamespaceEntry[],
    timing: PrecomputeTiming,
  ): PrecomputedCredential {
    const result: PrecomputedCredential = {
      prepareProof,
      prepareInstance,
      prepareWitness,
      credential: {
        jwt: credential.token,
        disclosures: credential.claims.map((c) => c.raw),
        deviceBindingKey: deviceKey,
      },
      birthdayClaimIndex,
      birthdayClaim,
      deviceKey,
      claimsPerCredential,
      normalizedClaimValues,
      claimNamespace,
      timing,

      serialize(): Uint8Array {
        return serializePrecomputed(result);
      },

      toJSON(): SerializedPrecomputedCredentialJSON {
        return {
          version: SDK_VERSION,
          prepareProof: base64Encode(result.prepareProof),
          prepareInstance: base64Encode(result.prepareInstance),
          prepareWitness: base64Encode(result.prepareWitness),
          credential: result.credential,
          birthdayClaimIndex: result.birthdayClaimIndex,
          birthdayClaim: result.birthdayClaim,
          deviceKey: result.deviceKey,
          claimsPerCredential: result.claimsPerCredential,
          normalizedClaimValues: result.normalizedClaimValues.map((value) =>
            value.toString(),
          ),
          claimNamespace: result.claimNamespace,
        };
      },
    };
    return result;
  }

  private buildPrecomputedMultiCredential(
    prepareProof: Uint8Array,
    prepareInstance: Uint8Array,
    prepareWitness: Uint8Array,
    credentials: Credential[],
    kind: MultiCredentialCircuitKind,
    deviceKey: EcdsaPublicKey,
    claimsPerCredential: number,
    normalizedClaimValues: bigint[],
    claimNamespace: ClaimNamespaceEntry[],
    timing: PrecomputeTiming,
  ): PrecomputedMultiCredential {
    const result: PrecomputedMultiCredential = {
      kind,
      prepareProof,
      prepareInstance,
      prepareWitness,
      credentials: credentials.map((credential) => ({
        jwt: credential.token,
        disclosures: credential.claims.map((c) => c.raw),
        deviceBindingKey: deviceKey,
      })),
      deviceKey,
      credentialCount: credentials.length,
      claimsPerCredential,
      normalizedClaimValues,
      claimNamespace,
      timing,

      serialize(): Uint8Array {
        return serializePrecomputedMulti(result);
      },

      toJSON(): SerializedPrecomputedMultiCredentialJSON {
        return {
          version: SDK_VERSION,
          kind: result.kind,
          prepareProof: base64Encode(result.prepareProof),
          prepareInstance: base64Encode(result.prepareInstance),
          prepareWitness: base64Encode(result.prepareWitness),
          credentials: result.credentials,
          deviceKey: result.deviceKey,
          credentialCount: result.credentialCount,
          claimsPerCredential: result.claimsPerCredential,
          normalizedClaimValues: result.normalizedClaimValues.map((value) =>
            value.toString(),
          ),
          claimNamespace: result.claimNamespace,
        };
      },
    };
    return result;
  }

  private buildPresentationProof(
    prepareProof: Uint8Array,
    prepareInstance: Uint8Array,
    showProof: Uint8Array,
    showInstance: Uint8Array,
    publicValues: ProofPublicValues,
    timing: PresentationTiming,
  ): PresentationProof {
    const result: PresentationProof = {
      prepareProof,
      prepareInstance,
      showProof,
      showInstance,
      publicValues,
      timing,

      serialize(): Uint8Array {
        return serializeProofBundle({
          prepareProof: result.prepareProof,
          showProof: result.showProof,
          prepareInstance: result.prepareInstance,
          showInstance: result.showInstance,
          publicValues: result.publicValues,
          timing: {
            generateBlindsMs: 0,
            prepareProveMs: 0,
            prepareReblindMs: 0,
            showProveMs: result.timing.showProveMs,
            showReblindMs: result.timing.presentMs,
            totalMs: result.timing.totalMs,
          },
          serialize: () => new Uint8Array(),
          toBase64: () => "",
          toJSON: () => ({} as SerializedProofJSON),
        });
      },

      toBase64(): string {
        return base64Encode(result.serialize());
      },

      toJSON(): SerializedProofJSON {
        return {
          version: SDK_VERSION,
          prepareProof: base64Encode(result.prepareProof),
          showProof: base64Encode(result.showProof),
          prepareInstance: base64Encode(result.prepareInstance),
          showInstance: base64Encode(result.showInstance),
          publicValues: {
            expressionResult: result.publicValues.expressionResult,
            deviceKeyX: result.publicValues.deviceKeyX,
            deviceKeyY: result.publicValues.deviceKeyY,
          },
        };
      },
    };
    return result;
  }
}

// Serialize a proof bundle into a single binary blob.
// Format: [4 bytes: length][bytes] for each of: version, prepareProof, showProof, prepareInstance, showInstance
function serializeProofBundle(result: ProofResult): Uint8Array {
  const version = new TextEncoder().encode(SDK_VERSION);
  const parts = [
    version,
    result.prepareProof,
    result.showProof,
    result.prepareInstance,
    result.showInstance,
  ];

  let totalSize = 0;
  for (const part of parts) {
    totalSize += 4 + part.length;
  }

  const buffer = new Uint8Array(totalSize);
  const view = new DataView(buffer.buffer);
  let offset = 0;

  for (const part of parts) {
    view.setUint32(offset, part.length, true);
    offset += 4;
    buffer.set(part, offset);
    offset += part.length;
  }

  return buffer;
}

export function deserializeProofBundle(data: Uint8Array): {
  version: string;
  prepareProof: Uint8Array;
  showProof: Uint8Array;
  prepareInstance: Uint8Array;
  showInstance: Uint8Array;
} {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = 0;

  function readPart(): Uint8Array {
    const len = view.getUint32(offset, true);
    offset += 4;
    const part = data.slice(offset, offset + len);
    offset += len;
    return part;
  }

  const versionBytes = readPart();
  const version = new TextDecoder().decode(versionBytes);
  const prepareProof = readPart();
  const showProof = readPart();
  const prepareInstance = readPart();
  const showInstance = readPart();

  return { version, prepareProof, showProof, prepareInstance, showInstance };
}

// Serialize a precomputed credential into JSON bytes
function serializePrecomputed(precomputed: PrecomputedCredential): Uint8Array {
  const json = JSON.stringify(precomputed.toJSON());
  return new TextEncoder().encode(json);
}

function serializePreparedMulti(prepared: PreparedMultiCredential): Uint8Array {
  const json = JSON.stringify(prepared.toJSON());
  return new TextEncoder().encode(json);
}

function serializePrecomputedMulti(
  precomputed: PrecomputedMultiCredential,
): Uint8Array {
  const json = JSON.stringify(precomputed.toJSON());
  return new TextEncoder().encode(json);
}

export function bundlePrecomputedCredentials(
  precomputedCredentials: PrecomputedCredential[],
): PreparedMultiCredential {
  if (precomputedCredentials.length < 2) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      "A multi-credential presentation requires at least two prepared credentials",
    );
  }

  const deviceKey = precomputedCredentials[0]!.deviceKey;
  const claimsPerCredential = precomputedCredentials[0]!.claimsPerCredential;
  for (const [index, precomputed] of precomputedCredentials.entries()) {
    if (precomputed.deviceKey.x !== deviceKey.x || precomputed.deviceKey.y !== deviceKey.y) {
      throw new InputError(
        "INVALID_KEY",
        `Prepared credential ${index} uses a different device binding key`,
      );
    }
    if (precomputed.claimsPerCredential !== claimsPerCredential) {
      throw new InputError(
        "PARAMS_EXCEEDED",
        "All prepared credentials in a bundle must use the same Prepare claim capacity",
      );
    }
  }

  const normalizedClaimValues = precomputedCredentials.flatMap(
    (precomputed) => precomputed.normalizedClaimValues,
  );
  const claimNamespace = precomputedCredentials.flatMap(
    (precomputed, credentialIndex) =>
      precomputed.claimNamespace.map((entry) => ({
        globalIndex: credentialIndex * claimsPerCredential + entry.claimIndex,
        credentialIndex,
        claimIndex: entry.claimIndex,
        claimName: entry.claimName,
      })),
  );

  const result: PreparedMultiCredential = {
    kind: `multi-vc-${precomputedCredentials.length}`,
    credentials: precomputedCredentials.map((precomputed) => precomputed.credential),
    deviceKey,
    credentialCount: precomputedCredentials.length,
    claimsPerCredential,
    normalizedClaimValues,
    claimNamespace,
    precomputedCredentials,

    serialize(): Uint8Array {
      return serializePreparedMulti(result);
    },

    toJSON(): SerializedPreparedMultiCredentialJSON {
      return {
        version: SDK_VERSION,
        kind: result.kind,
        credentials: result.credentials,
        deviceKey: result.deviceKey,
        credentialCount: result.credentialCount,
        claimsPerCredential: result.claimsPerCredential,
        normalizedClaimValues: result.normalizedClaimValues.map((value) =>
          value.toString(),
        ),
        claimNamespace: result.claimNamespace,
        precomputedCredentials: result.precomputedCredentials.map((precomputed) =>
          precomputed.toJSON(),
        ),
      };
    },
  };
  return result;
}

// Deserialize a precomputed credential from JSON bytes
export function deserializePrecomputed(data: Uint8Array): PrecomputedCredential {
  const json: SerializedPrecomputedCredentialJSON = JSON.parse(
    new TextDecoder().decode(data),
  );

  const claimsPerCredential = json.claimsPerCredential ?? 0;
  const normalizedClaimValues = (json.normalizedClaimValues ?? []).map((value) =>
    BigInt(value),
  );
  const result: PrecomputedCredential = {
    prepareProof: base64Decode(json.prepareProof),
    prepareInstance: base64Decode(json.prepareInstance),
    prepareWitness: base64Decode(json.prepareWitness),
    credential: json.credential,
    birthdayClaimIndex: json.birthdayClaimIndex,
    birthdayClaim: json.birthdayClaim,
    deviceKey: json.deviceKey,
    claimsPerCredential,
    normalizedClaimValues,
    claimNamespace: json.claimNamespace ?? [],
    timing: {
      parseCredentialMs: 0,
      buildInputsMs: 0,
      prepareWitnessMs: 0,
      prepareProveMs: 0,
      totalMs: 0,
    },

    serialize(): Uint8Array {
      return serializePrecomputed(result);
    },

    toJSON(): SerializedPrecomputedCredentialJSON {
      return {
        ...json,
        claimsPerCredential: result.claimsPerCredential,
        normalizedClaimValues: result.normalizedClaimValues.map((value) =>
          value.toString(),
        ),
        claimNamespace: result.claimNamespace,
      };
    },
  };

  return result;
}

export function deserializePreparedMulti(
  data: Uint8Array,
): PreparedMultiCredential {
  const json: SerializedPreparedMultiCredentialJSON = JSON.parse(
    new TextDecoder().decode(data),
  );
  const precomputedCredentials = json.precomputedCredentials.map((entry) =>
    deserializePrecomputed(
      new TextEncoder().encode(JSON.stringify(entry)),
    ),
  );
  const normalizedClaimValues = json.normalizedClaimValues.map((value) =>
    BigInt(value),
  );
  const result: PreparedMultiCredential = {
    kind: json.kind,
    credentials: json.credentials,
    deviceKey: json.deviceKey,
    credentialCount: json.credentialCount,
    claimsPerCredential: json.claimsPerCredential,
    normalizedClaimValues,
    claimNamespace: json.claimNamespace,
    precomputedCredentials,

    serialize(): Uint8Array {
      return serializePreparedMulti(result);
    },

    toJSON(): SerializedPreparedMultiCredentialJSON {
      return json;
    },
  };
  return result;
}

export function deserializePrecomputedMulti(
  data: Uint8Array,
): PrecomputedMultiCredential {
  const json: SerializedPrecomputedMultiCredentialJSON = JSON.parse(
    new TextDecoder().decode(data),
  );

  const normalizedClaimValues = json.normalizedClaimValues.map((value) =>
    BigInt(value),
  );
  const result: PrecomputedMultiCredential = {
    kind: json.kind,
    prepareProof: base64Decode(json.prepareProof),
    prepareInstance: base64Decode(json.prepareInstance),
    prepareWitness: base64Decode(json.prepareWitness),
    credentials: json.credentials,
    deviceKey: json.deviceKey,
    credentialCount: json.credentialCount,
    claimsPerCredential: json.claimsPerCredential,
    normalizedClaimValues,
    claimNamespace: json.claimNamespace,
    timing: {
      parseCredentialMs: 0,
      buildInputsMs: 0,
      prepareWitnessMs: 0,
      prepareProveMs: 0,
      totalMs: 0,
    },

    serialize(): Uint8Array {
      return serializePrecomputedMulti(result);
    },

    toJSON(): SerializedPrecomputedMultiCredentialJSON {
      return json;
    },
  };

  return result;
}

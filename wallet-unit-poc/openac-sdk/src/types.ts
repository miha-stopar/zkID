export interface OpenACConfig {
  wasmPath?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  wasmModule?: any;
  assetsDir?: string;
  artifacts?: CircuitArtifacts;
  memory?: { initial?: number; maximum?: number };
}

export interface CircuitArtifacts {
  prepareR1cs?: Uint8Array | string;
  showR1cs?: Uint8Array | string;
  prepareWitnessWasm?: Uint8Array | string;
  showWitnessWasm?: Uint8Array | string;
}

export interface JwtCircuitParams {
  maxMessageLength: number;
  maxB64PayloadLength: number;
  maxMatches: number;
  maxSubstringLength: number;
  maxClaimLength: number;
}

export interface ShowCircuitParams {
  nClaims: number;
  maxPredicates: number;
  maxLogicTokens: number;
  valueBits: number;
}

// Default circuit parameters matching production circom configuration
export const DEFAULT_JWT_PARAMS: JwtCircuitParams = {
  maxMessageLength: 1920,
  maxB64PayloadLength: 1900,
  maxMatches: 4,
  maxSubstringLength: 50,
  maxClaimLength: 128,
};

export const DEFAULT_JWT_1K_PARAMS: JwtCircuitParams = {
  maxMessageLength: 1280,
  maxB64PayloadLength: 960,
  maxMatches: 4,
  maxSubstringLength: 50,
  maxClaimLength: 128,
};

export const DEFAULT_SHOW_PARAMS: ShowCircuitParams = {
  nClaims: 2,
  maxPredicates: 2,
  maxLogicTokens: 8,
  valueBits: 64,
};

export const DEFAULT_SHOW_2VC_PARAMS: ShowCircuitParams = {
  ...DEFAULT_SHOW_PARAMS,
  nClaims: DEFAULT_SHOW_PARAMS.nClaims * 2,
};

// ECDSA P-256 public key in JWK format
export interface EcdsaPublicKey {
  kty: "EC";
  crv: "P-256";
  x: string; // base64url-encoded X coordinate
  y: string; // base64url-encoded Y coordinate
  kid?: string;
}

export type EcdsaPrivateKey = string | Uint8Array;

export interface PemPublicKey {
  pem: string;
}

export type IssuerPublicKey = EcdsaPublicKey | PemPublicKey;

export interface ProofRequest {
  jwt: string;
  disclosures: string[];
  issuerPublicKey: IssuerPublicKey;
  devicePrivateKey: EcdsaPrivateKey;
  verifierNonce: string;
  birthdayClaimIndex?: number;
  currentDate?: Date;
  keys?: KeySet;
  jwtParams?: JwtCircuitParams;
  showParams?: ShowCircuitParams;
  decodeFlags?: number[];
  additionalMatches?: string[];
}

export interface ProofResult {
  prepareProof: Uint8Array;
  showProof: Uint8Array;
  prepareInstance: Uint8Array;
  showInstance: Uint8Array;
  publicValues: ProofPublicValues;
  timing: ProofTiming;
  serialize(): Uint8Array;
  toBase64(): string;
  toJSON(): SerializedProofJSON;
}

export interface ProofPublicValues {
  expressionResult: boolean;
  deviceKeyX: string;
  deviceKeyY: string;
  normalizedClaimValues: bigint[];
}

export interface ProofTiming {
  setupMs?: number;
  generateBlindsMs: number;
  prepareProveMs: number;
  prepareReblindMs: number;
  showProveMs: number;
  showReblindMs: number;
  totalMs: number;
}

export interface VerifyingKeys {
  prepareVerifyingKey: Uint8Array;
  showVerifyingKey: Uint8Array;
}

export interface VerificationResult {
  valid: boolean;
  expressionResult: boolean | null;
  deviceKey: { x: string; y: string } | null;
  verifyMs: number;
  error?: string;
}

export interface KeySet {
  prepareProvingKey: Uint8Array;
  prepareVerifyingKey: Uint8Array;
  showProvingKey: Uint8Array;
  showVerifyingKey: Uint8Array;
  jwtParams?: JwtCircuitParams;
  verifyingKeys(): VerifyingKeys;
  serialize(): SerializedKeySet;
}

export interface PreparedMultiKeySet extends KeySet {
  linkProvingKey: Uint8Array;
  linkVerifyingKey: Uint8Array;
  credentialCount?: number;
  keySetId?: string;
  preparedMultiVerifyingKeys(): PreparedMultiVerifyingKeys;
  serialize(): SerializedPreparedMultiKeySet;
}

export interface SerializedKeySet {
  prepareProvingKey: Uint8Array;
  prepareVerifyingKey: Uint8Array;
  showProvingKey: Uint8Array;
  showVerifyingKey: Uint8Array;
  jwtParams?: JwtCircuitParams;
}

export interface SerializedPreparedMultiKeySet extends SerializedKeySet {
  linkProvingKey: Uint8Array;
  linkVerifyingKey: Uint8Array;
  credentialCount?: number;
  keySetId?: string;
}

export interface PreparedMultiVerifyingKeys extends VerifyingKeys {
  linkVerifyingKey: Uint8Array;
  credentialCount?: number;
  keySetId?: string;
}

export interface SerializedProofJSON {
  version: string;
  prepareProof: string; // base64
  showProof: string; // base64
  prepareInstance: string; // base64
  showInstance: string; // base64
  publicValues: {
    expressionResult: boolean;
    deviceKeyX: string;
    deviceKeyY: string;
  };
}

export interface SerializedPreparedMultiPresentationProofJSON {
  version: string;
  kind: MultiCredentialCircuitKind;
  credentialCount: number;
  claimsPerCredential: number;
  prepareProofs: string[]; // base64
  linkProof: string; // base64
  linkInstance: string; // base64
  showProof: string; // base64
  showInstance: string; // base64
  publicValues: {
    expressionResult: boolean;
    deviceKeyX: string;
    deviceKeyY: string;
    normalizedClaimValues: string[];
  };
}

export type SerializedProof = Uint8Array;

export type ErrorCode =
  | "SETUP_FAILED"
  | "KEYS_NOT_FOUND"
  | "PROOF_GENERATION_FAILED"
  | "WITNESS_GENERATION_FAILED"
  | "REBLIND_FAILED"
  | "VERIFICATION_FAILED"
  | "INVALID_PROOF_FORMAT"
  | "COMMITMENT_MISMATCH"
  | "INVALID_JWT"
  | "INVALID_KEY"
  | "INVALID_SIGNATURE"
  | "MISSING_DISCLOSURE"
  | "BIRTHDAY_NOT_FOUND"
  | "CLAIM_NOT_FOUND"
  | "PARAMS_EXCEEDED"
  | "WASM_LOAD_FAILED"
  | "WASM_OOM"
  | "WASM_NOT_INITIALIZED";

// A parsed SD-JWT disclosure
export interface DisclosedClaim {
  index: number;
  salt: string;
  name: string;
  value: string;
  raw: string;
  digest: string; // SHA-256 of disclosure (base64url, matches _sd array)
}

// Raw WASM module exports (internal)
export interface WasmExports {
  setup_prepare(
    r1csBytes: Uint8Array,
  ): Promise<{ pk: Uint8Array; vk: Uint8Array }>;
  setup_show(
    r1csBytes: Uint8Array,
  ): Promise<{ pk: Uint8Array; vk: Uint8Array }>;

  prove_prepare(
    pk: Uint8Array,
    witness: Uint8Array,
  ): Promise<{ proof: Uint8Array; instance: Uint8Array; witness: Uint8Array }>;
  prove_show(
    pk: Uint8Array,
    witness: Uint8Array,
  ): Promise<{ proof: Uint8Array; instance: Uint8Array; witness: Uint8Array }>;

  reblind(
    pk: Uint8Array,
    instance: Uint8Array,
    witness: Uint8Array,
    blinds: Uint8Array,
  ): Promise<{ proof: Uint8Array; instance: Uint8Array; witness: Uint8Array }>;

  verify(
    proof: Uint8Array,
    vk: Uint8Array,
  ): Promise<{ valid: boolean; publicValues: bigint[] }>;

  generate_shared_blinds(count: number): Promise<Uint8Array>;

  generate_witness(
    inputsJson: string,
    circuitWasm: Uint8Array,
  ): Promise<Uint8Array>;
}

// Raw circuit inputs for the JWT (Prepare) circuit
export interface JwtCircuitInputs {
  sig_r: bigint;
  sig_s_inverse: bigint;
  pubKeyX: bigint;
  pubKeyY: bigint;
  message: bigint[];
  messageLength: number;
  periodIndex: number;
  matchesCount: number;
  matchSubstring: bigint[][];
  matchLength: number[];
  matchIndex: number[];
  claims: bigint[][];
  claimLengths: bigint[];
  decodeFlags: number[];
  claimFormats: bigint[];
}

// Raw circuit inputs for the Show circuit
export interface ShowCircuitInputs {
  deviceKeyX: bigint;
  deviceKeyY: bigint;
  sig_r: bigint;
  sig_s_inverse: bigint;
  messageHash: bigint;
  predicateLen: bigint;
  claimValues: bigint[];
  predicateClaimRefs: bigint[];
  predicateOps: bigint[];
  predicateRhsIsRef: bigint[];
  predicateRhsValues: bigint[];
  tokenTypes: bigint[];
  tokenValues: bigint[];
  exprLen: bigint;
}

export interface PrecomputeRequest {
  jwt: string;
  disclosures: string[];
  issuerPublicKey: IssuerPublicKey;
  keys: KeySet;
  jwtParams?: JwtCircuitParams;
  birthdayClaimIndex?: number;
  decodeFlags?: number[];
  claimFormats?: number[];
  additionalMatches?: string[];
}

export interface MultiCredentialInput {
  jwt: string;
  disclosures: string[];
  issuerPublicKey: IssuerPublicKey;
  decodeFlags?: number[];
  claimFormats?: number[];
  additionalMatches?: string[];
}

export interface SerializedCredential {
  jwt: string;
  disclosures: string[];
  deviceBindingKey: EcdsaPublicKey;
}

export interface ClaimNamespaceEntry {
  globalIndex: number;
  credentialIndex: number;
  claimIndex: number;
  claimName: string;
}

export type MultiCredentialCircuitKind = `multi-vc-${number}`;

export interface PrecomputedCredential {
  prepareProof: Uint8Array;
  prepareInstance: Uint8Array;
  prepareWitness: Uint8Array;
  credential: SerializedCredential;
  birthdayClaimIndex: number;
  birthdayClaim: string;
  deviceKey: EcdsaPublicKey;
  claimsPerCredential: number;
  normalizedClaimValues: bigint[];
  claimNamespace: ClaimNamespaceEntry[];
  timing: PrecomputeTiming;
  serialize(): Uint8Array;
  toJSON(): SerializedPrecomputedCredentialJSON;
}

export interface PrecomputePreparedMultiRequest {
  credentials: MultiCredentialInput[];
  keys: KeySet;
  credentialCount?: number;
  jwtParams?: JwtCircuitParams;
}

export interface PreparedMultiCredential {
  kind: MultiCredentialCircuitKind;
  credentials: SerializedCredential[];
  deviceKey: EcdsaPublicKey;
  credentialCount: number;
  claimsPerCredential: number;
  normalizedClaimValues: bigint[];
  claimNamespace: ClaimNamespaceEntry[];
  precomputedCredentials: PrecomputedCredential[];
  serialize(): Uint8Array;
  toJSON(): SerializedPreparedMultiCredentialJSON;
}

export interface PreparedMultiShowRequest {
  prepared: PreparedMultiCredential;
  verifierNonce: string;
  devicePrivateKey: EcdsaPrivateKey;
  keys: Pick<KeySet, "showProvingKey">;
  showParams?: ShowCircuitParams;
  showInputOptions?: import("./inputs/show-input-builder.js").ShowInputOptions;
}

export interface PreparedMultiShowProof {
  kind: MultiCredentialCircuitKind;
  credentialCount: number;
  showProof: Uint8Array;
  showInstance: Uint8Array;
  showWitness: Uint8Array;
  publicValues: ProofPublicValues;
  timing: PreparedMultiShowTiming;
}

export interface PreparedMultiPresentationRequest {
  prepared: PreparedMultiCredential;
  verifierNonce: string;
  devicePrivateKey: EcdsaPrivateKey;
  keys: PreparedMultiKeySet;
  showParams?: ShowCircuitParams;
  showInputOptions?: import("./inputs/show-input-builder.js").ShowInputOptions;
}

export interface PreparedMultiPresentationProof {
  kind: MultiCredentialCircuitKind;
  credentialCount: number;
  claimsPerCredential: number;
  prepareProofs: Uint8Array[];
  linkProof: Uint8Array;
  linkInstance: Uint8Array;
  showProof: Uint8Array;
  showInstance: Uint8Array;
  publicValues: ProofPublicValues;
  timing: PresentationTiming;
  serialize(): Uint8Array;
  toBase64(): string;
  toJSON(): SerializedPreparedMultiPresentationProofJSON;
}

export interface VerifyPreparedMultiRequest {
  proof: PreparedMultiPresentationProof;
  keys: PreparedMultiVerifyingKeys;
  expected: PreparedMultiVerificationOptions;
}

export interface PreparedMultiVerificationOptions {
  expectedCredentialCount: number;
  verifierNonce: string;
  showInputOptions: import("./inputs/show-input-builder.js").ShowInputOptions;
  showParams?: ShowCircuitParams;
  expectedClaimsPerCredential?: number;
  expectedKeySetId?: string;
  requireExpressionResult?: boolean;
}

export interface PreparedMultiChallengeRequest {
  nonce: string;
  credentialCount: number;
  claimsPerCredential: number;
  showParams: ShowCircuitParams;
  showInputOptions: import("./inputs/show-input-builder.js").ShowInputOptions;
  keySetId?: string;
}

export interface PrecomputeTiming {
  parseCredentialMs: number;
  buildInputsMs: number;
  prepareWitnessMs: number;
  prepareProveMs: number;
  totalMs: number;
}

export interface SerializedPrecomputedCredentialJSON {
  version: string;
  prepareProof: string;
  prepareInstance: string;
  prepareWitness: string;
  credential: SerializedCredential;
  birthdayClaimIndex: number;
  birthdayClaim: string;
  deviceKey: EcdsaPublicKey;
  claimsPerCredential?: number;
  normalizedClaimValues?: string[];
  claimNamespace?: ClaimNamespaceEntry[];
}

export interface SerializedPreparedMultiCredentialJSON {
  version: string;
  kind: MultiCredentialCircuitKind;
  credentials: SerializedCredential[];
  deviceKey: EcdsaPublicKey;
  credentialCount: number;
  claimsPerCredential: number;
  normalizedClaimValues: string[];
  claimNamespace: ClaimNamespaceEntry[];
  precomputedCredentials: SerializedPrecomputedCredentialJSON[];
}

export interface PresentRequest {
  precomputed: PrecomputedCredential;
  verifierNonce: string;
  devicePrivateKey: EcdsaPrivateKey;
  keys: KeySet;
  showParams?: ShowCircuitParams;
  showInputOptions?: import("./inputs/show-input-builder.js").ShowInputOptions;
}

export interface PresentationProof {
  prepareProof: Uint8Array;
  prepareInstance: Uint8Array;
  showProof: Uint8Array;
  showInstance: Uint8Array;
  publicValues: ProofPublicValues;
  timing: PresentationTiming;
  serialize(): Uint8Array;
  toBase64(): string;
  toJSON(): SerializedProofJSON;
}

export interface PresentationTiming {
  showWitnessMs: number;
  showProveMs: number;
  presentMs: number;
  totalMs: number;
}

export interface PreparedMultiShowTiming {
  showWitnessMs: number;
  showProveMs: number;
  totalMs: number;
}

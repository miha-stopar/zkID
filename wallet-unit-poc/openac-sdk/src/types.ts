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
  maxClaimsLength: number;
}

// Default circuit parameters matching production circom configuration
export const DEFAULT_JWT_PARAMS: JwtCircuitParams = {
  maxMessageLength: 1920,
  maxB64PayloadLength: 1900,
  maxMatches: 4,
  maxSubstringLength: 50,
  maxClaimLength: 128,
};

export const DEFAULT_SHOW_PARAMS: ShowCircuitParams = {
  maxClaimsLength: 128,
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
  ageAbove18: boolean;
  deviceKeyX: string;
  deviceKeyY: string;
  ageClaim: bigint[];
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
  ageAbove18: boolean | null;
  deviceKey: { x: string; y: string } | null;
  verifyMs: number;
  error?: string;
}

export interface KeySet {
  prepareProvingKey: Uint8Array;
  prepareVerifyingKey: Uint8Array;
  showProvingKey: Uint8Array;
  showVerifyingKey: Uint8Array;
  verifyingKeys(): VerifyingKeys;
  serialize(): SerializedKeySet;
}

export interface SerializedKeySet {
  prepareProvingKey: Uint8Array;
  prepareVerifyingKey: Uint8Array;
  showProvingKey: Uint8Array;
  showVerifyingKey: Uint8Array;
}

export interface SerializedProofJSON {
  version: string;
  prepareProof: string; // base64
  showProof: string; // base64
  prepareInstance: string; // base64
  showInstance: string; // base64
  publicValues: {
    ageAbove18: boolean;
    deviceKeyX: string;
    deviceKeyY: string;
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
  ageClaimIndex: number;
}

// Raw circuit inputs for the Show circuit
export interface ShowCircuitInputs {
  deviceKeyX: bigint;
  deviceKeyY: bigint;
  sig_r: bigint;
  sig_s_inverse: bigint;
  messageHash: bigint;
  claim: bigint[];
  currentYear: bigint;
  currentMonth: bigint;
  currentDay: bigint;
}

export interface PrecomputeRequest {
  jwt: string;
  disclosures: string[];
  issuerPublicKey: IssuerPublicKey;
  keys: KeySet;
  jwtParams?: JwtCircuitParams;
  birthdayClaimIndex?: number;
  decodeFlags?: number[];
  additionalMatches?: string[];
}

export interface SerializedCredential {
  jwt: string;
  disclosures: string[];
  deviceBindingKey: EcdsaPublicKey;
}

export interface PrecomputedCredential {
  prepareProof: Uint8Array;
  prepareInstance: Uint8Array;
  prepareWitness: Uint8Array;
  credential: SerializedCredential;
  birthdayClaimIndex: number;
  birthdayClaim: string;
  deviceKey: EcdsaPublicKey;
  timing: PrecomputeTiming;
  serialize(): Uint8Array;
  toJSON(): SerializedPrecomputedCredentialJSON;
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
}

export interface PresentRequest {
  precomputed: PrecomputedCredential;
  verifierNonce: string;
  devicePrivateKey: EcdsaPrivateKey;
  keys: KeySet;
  currentDate?: Date;
  showParams?: ShowCircuitParams;
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

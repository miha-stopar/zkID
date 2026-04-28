import { InputError } from "./errors.js";
import {
  DEFAULT_JWT_1K_PARAMS,
  DEFAULT_SHOW_PARAMS,
} from "./types.js";
import { buildPrepare2VcCircuitInputs } from "./inputs/jwt-input-builder.js";
import type {
  JwtCircuitInputs,
  JwtCircuitParams,
  MultiCredentialCircuitKind,
  Prepare2VcCircuitInputs,
  ShowCircuitParams,
} from "./types.js";
import type { VcSize } from "./wasm-bridge.js";

export type MultiPrepareCircuitInputs =
  | Prepare2VcCircuitInputs
  | Record<string, unknown>;

export type WasmPrecomputeExportName =
  `precompute_${string}_from_witness`;

export interface MultiCredentialCircuitProfile {
  credentialCount: number;
  kind: MultiCredentialCircuitKind;
  prepareCircuitStem: string;
  showCircuitStem: string;
  prepareCliName: string;
  showCliName: string;
  prepareWasmExport: WasmPrecomputeExportName;
  showWasmExport: WasmPrecomputeExportName;
  prepareWitnessWasm: string;
  showWitnessWasm: string;
  defaultJwtParams: JwtCircuitParams;
  defaultShowParams: ShowCircuitParams;
  buildPrepareInputs(inputs: JwtCircuitInputs[]): MultiPrepareCircuitInputs;
}

export const SUPPORTED_MULTI_CREDENTIAL_COUNTS = [2] as const;

const TWO_CREDENTIAL_PROFILE: MultiCredentialCircuitProfile = {
  credentialCount: 2,
  kind: "multi-vc-2",
  prepareCircuitStem: "prepare_2vc",
  showCircuitStem: "show_2vc",
  prepareCliName: "prepare-2vc",
  showCliName: "show-2vc",
  prepareWasmExport: "precompute_prepare_2vc_from_witness",
  showWasmExport: "precompute_show_2vc_from_witness",
  prepareWitnessWasm: "prepare_2vc.wasm",
  showWitnessWasm: "show_2vc.wasm",
  defaultJwtParams: DEFAULT_JWT_1K_PARAMS,
  defaultShowParams: {
    ...DEFAULT_SHOW_PARAMS,
    nClaims: DEFAULT_SHOW_PARAMS.nClaims * 2,
  },
  buildPrepareInputs(inputs: JwtCircuitInputs[]): Prepare2VcCircuitInputs {
    if (inputs.length !== 2) {
      throw unsupportedCountError(inputs.length);
    }
    return buildPrepare2VcCircuitInputs(inputs[0]!, inputs[1]!);
  },
};

const PROFILES = new Map<number, MultiCredentialCircuitProfile>([
  [TWO_CREDENTIAL_PROFILE.credentialCount, TWO_CREDENTIAL_PROFILE],
]);

export function getMultiCredentialCircuitProfile(
  credentialCount: number,
): MultiCredentialCircuitProfile {
  const profile = PROFILES.get(credentialCount);
  if (!profile) {
    throw unsupportedCountError(credentialCount);
  }
  return profile;
}

export function multiCredentialKeyFilenames(
  credentialCount: number,
  vcSize: VcSize,
): [string, string, string, string] {
  const profile = getMultiCredentialCircuitProfile(credentialCount);
  const prefix = `${vcSize}_`;
  return [
    `${prefix}${profile.prepareCircuitStem}_proving.key`,
    `${prefix}${profile.prepareCircuitStem}_verifying.key`,
    `${prefix}${profile.showCircuitStem}_proving.key`,
    `${prefix}${profile.showCircuitStem}_verifying.key`,
  ];
}

function unsupportedCountError(credentialCount: number): InputError {
  return new InputError(
    "PARAMS_EXCEEDED",
    `Unsupported multi-credential count ${credentialCount}. Supported counts: ${SUPPORTED_MULTI_CREDENTIAL_COUNTS.join(", ")}`,
  );
}

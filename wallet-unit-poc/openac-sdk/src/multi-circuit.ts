import { InputError } from "./errors.js";
import {
  DEFAULT_JWT_PARAMS,
  DEFAULT_JWT_1K_PARAMS,
  DEFAULT_SHOW_PARAMS,
} from "./types.js";
import { buildPrepare2VcCircuitInputs } from "./inputs/jwt-input-builder.js";
import type {
  JwtCircuitInputs,
  JwtCircuitParams,
  MultiCredentialCircuitKind,
  PrepareMultiVcCircuitInputs,
  Prepare2VcCircuitInputs,
  ShowCircuitParams,
} from "./types.js";
import type { VcSize } from "./wasm-bridge.js";

export type MultiPrepareCircuitInputs =
  | Prepare2VcCircuitInputs
  | PrepareMultiVcCircuitInputs
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

export interface PreparedMultiShowCircuitProfile {
  credentialCount: number;
  kind: MultiCredentialCircuitKind;
  showCircuitStem: string;
  linkCircuitStem: string;
  showCliName: string;
  linkCliName: string;
  showWasmExport: WasmPrecomputeExportName;
  linkWasmExport: WasmPrecomputeExportName;
  showWitnessWasm: string;
  linkWitnessWasm: string;
  defaultShowParams: ShowCircuitParams;
}

export const SUPPORTED_MULTI_CREDENTIAL_COUNTS = [2] as const;
export const SUPPORTED_PREPARED_MULTI_CREDENTIAL_COUNTS = [2, 3, 4] as const;

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
  defaultShowParams: showParamsForCredentialCount(2),
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

const PREPARED_MULTI_SHOW_PROFILES = new Map<number, PreparedMultiShowCircuitProfile>(
  SUPPORTED_PREPARED_MULTI_CREDENTIAL_COUNTS.map((credentialCount) => [
    credentialCount,
    {
      credentialCount,
      kind: `multi-vc-${credentialCount}` as MultiCredentialCircuitKind,
      showCircuitStem: `show_${credentialCount}vc`,
      linkCircuitStem: `link_${credentialCount}vc`,
      showCliName: `show-${credentialCount}vc`,
      linkCliName: `link-${credentialCount}vc`,
      showWasmExport: `precompute_show_${credentialCount}vc_from_witness`,
      linkWasmExport: `precompute_link_${credentialCount}vc_from_witness`,
      showWitnessWasm: `show_${credentialCount}vc.wasm`,
      linkWitnessWasm: `link_${credentialCount}vc.wasm`,
      defaultShowParams: showParamsForCredentialCount(credentialCount),
    },
  ]),
);

export function getMultiCredentialCircuitProfile(
  credentialCount: number,
): MultiCredentialCircuitProfile {
  const profile = PROFILES.get(credentialCount);
  if (!profile) {
    throw unsupportedCountError(credentialCount);
  }
  return profile;
}

export function getPreparedMultiShowCircuitProfile(
  credentialCount: number,
): PreparedMultiShowCircuitProfile {
  const profile = PREPARED_MULTI_SHOW_PROFILES.get(credentialCount);
  if (!profile) {
    throw unsupportedPreparedMultiShowCountError(credentialCount);
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

export function preparedMultiKeyFilenames(
  credentialCount: number,
  vcSize: VcSize,
): [string, string, string, string, string, string] {
  const profile = getPreparedMultiShowCircuitProfile(credentialCount);
  const prefix = `${vcSize}_`;
  return [
    `${prefix}prepare_proving.key`,
    `${prefix}prepare_verifying.key`,
    `${prefix}${profile.showCircuitStem}_proving.key`,
    `${prefix}${profile.showCircuitStem}_verifying.key`,
    `${prefix}${profile.linkCircuitStem}_proving.key`,
    `${prefix}${profile.linkCircuitStem}_verifying.key`,
  ];
}

export function preparedMultiShowKeyFilenames(
  credentialCount: number,
  vcSize: VcSize,
): [string, string] {
  const profile = getPreparedMultiShowCircuitProfile(credentialCount);
  const prefix = `${vcSize}_`;
  return [
    `${prefix}${profile.showCircuitStem}_proving.key`,
    `${prefix}${profile.showCircuitStem}_verifying.key`,
  ];
}

export function jwtParamsForVcSize(vcSize: VcSize): JwtCircuitParams {
  switch (vcSize) {
    case "1k":
      return DEFAULT_JWT_1K_PARAMS;
    case "2k":
      return {
        ...DEFAULT_JWT_PARAMS,
        maxMessageLength: 2048,
        maxB64PayloadLength: 2000,
      };
    case "4k":
      return {
        ...DEFAULT_JWT_PARAMS,
        maxMessageLength: 4096,
        maxB64PayloadLength: 4000,
      };
    case "8k":
      return {
        ...DEFAULT_JWT_PARAMS,
        maxMessageLength: 8192,
        maxB64PayloadLength: 8000,
      };
  }
}

function showParamsForCredentialCount(credentialCount: number): ShowCircuitParams {
  return {
    ...DEFAULT_SHOW_PARAMS,
    nClaims: DEFAULT_SHOW_PARAMS.nClaims * credentialCount,
  };
}

function unsupportedCountError(credentialCount: number): InputError {
  return new InputError(
    "PARAMS_EXCEEDED",
    `Unsupported multi-credential count ${credentialCount}. Supported counts: ${SUPPORTED_MULTI_CREDENTIAL_COUNTS.join(", ")}`,
  );
}

function unsupportedPreparedMultiShowCountError(
  credentialCount: number,
): InputError {
  return new InputError(
    "PARAMS_EXCEEDED",
    `Unsupported prepared multi-credential Show count ${credentialCount}. Supported counts: ${SUPPORTED_PREPARED_MULTI_CREDENTIAL_COUNTS.join(", ")}`,
  );
}

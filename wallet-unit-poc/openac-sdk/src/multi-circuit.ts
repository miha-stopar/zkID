import { InputError } from "./errors.js";
import {
  DEFAULT_JWT_PARAMS,
  DEFAULT_JWT_1K_PARAMS,
  DEFAULT_SHOW_PARAMS,
} from "./types.js";
import type {
  JwtCircuitParams,
  MultiCredentialCircuitKind,
  ShowCircuitParams,
} from "./types.js";
import type { VcSize } from "./wasm-bridge.js";

export type WasmPrecomputeExportName =
  `precompute_${string}_from_witness`;

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

export const SUPPORTED_PREPARED_MULTI_CREDENTIAL_COUNTS = [2, 3, 4] as const;

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

export function getPreparedMultiShowCircuitProfile(
  credentialCount: number,
): PreparedMultiShowCircuitProfile {
  const profile = PREPARED_MULTI_SHOW_PROFILES.get(credentialCount);
  if (!profile) {
    throw unsupportedPreparedMultiShowCountError(credentialCount);
  }
  return profile;
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

export function preparedMultiKeySetId(
  vcSize: VcSize,
  credentialCount: number,
): string {
  getPreparedMultiShowCircuitProfile(credentialCount);
  return `${vcSize}-prepared-multi-${credentialCount}`;
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

function unsupportedPreparedMultiShowCountError(
  credentialCount: number,
): InputError {
  return new InputError(
    "PARAMS_EXCEEDED",
    `Unsupported prepared multi-credential Show count ${credentialCount}. Supported counts: ${SUPPORTED_PREPARED_MULTI_CREDENTIAL_COUNTS.join(", ")}`,
  );
}

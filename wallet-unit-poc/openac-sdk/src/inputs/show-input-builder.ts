import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";
import { Field } from "@noble/curves/abstract/modular";

import {
  base64urlToBigInt,
  base64urlEncode,
  bytesToBigInt,
  P256_SCALAR_ORDER,
  sha256HashString,
} from "../utils.js";
import { InputError } from "../errors.js";
import type {
  PreparedMultiChallengeRequest,
  ShowCircuitParams,
  ShowCircuitInputs,
  EcdsaPublicKey,
  EcdsaPrivateKey,
} from "../types.js";

const Fq = Field(BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"));

export function signDeviceNonce(nonce: string, privateKey: EcdsaPrivateKey): string {
  const privateKeyBytes =
    typeof privateKey === "string"
      ? hexToBytes(privateKey)
      : privateKey;

  const messageHash = sha256(new TextEncoder().encode(nonce));
  const signature = p256.sign(messageHash, privateKeyBytes);

  return bytesToBase64url(signature.toCompactRawBytes());
}

/** Predicate operator codes matching eval-predicate.circom */
export const PredicateOp = {
  LE: 0,
  GE: 1,
  EQ: 2,
} as const;

/** Logic token types for postfix expression evaluation */
export const LogicToken = {
  REF: 0,
  AND: 1,
  OR: 2,
  NOT: 3,
} as const;

export interface PredicateSpec {
  claimRef: number;
  op: number;
  /** True when rhsValue is a claim reference, false when rhsValue is a literal. */
  rhsIsRef?: boolean;
  /** Literal comparison value, or RHS claim index when rhsIsRef is true. */
  rhsValue?: bigint;
  /** @deprecated Use rhsValue. Kept as a compatibility alias for literal predicates. */
  compareValue?: bigint;
}

export interface ShowInputOptions {
  /** Normalized claim values (from JWT circuit output). */
  normalizedClaimValues?: bigint[];
  /** Predicate specifications. Defaults to a single EQ literal predicate on claim 0. */
  predicates?: PredicateSpec[];
  /** Postfix logic expression as [tokenType, tokenValue] pairs. Defaults to REF(0). */
  logicExpression?: Array<{ type: number; value: number }>;
}

export interface ShowPolicyPublicInputs {
  messageHash: bigint;
  predicateLen: bigint;
  predicateClaimRefs: bigint[];
  predicateOps: bigint[];
  predicateRhsIsRef: bigint[];
  predicateRhsValues: bigint[];
  tokenTypes: bigint[];
  tokenValues: bigint[];
  exprLen: bigint;
}

export function buildShowCircuitInputs(
  params: ShowCircuitParams,
  nonce: string,
  deviceSignature: string,
  deviceKey: EcdsaPublicKey,
  options: ShowInputOptions = {},
): ShowCircuitInputs {
  // decode the device signature
  const sigBytes = base64Decode(deviceSignature);
  const sigHex = Array.from(sigBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const sigDecoded = p256.Signature.fromCompact(sigHex);
  const sigSInverse = Fq.inv(sigDecoded.s);

  // decode device key
  if (deviceKey.kty !== "EC" || deviceKey.crv !== "P-256") {
    throw new InputError("INVALID_KEY", "Device key must be P-256 EC key");
  }
  const deviceKeyX = base64urlToBigInt(deviceKey.x);
  const deviceKeyY = base64urlToBigInt(deviceKey.y);

  // verify signature off-chain
  const pubkey = p256.ProjectivePoint.fromAffine({ x: deviceKeyX, y: deviceKeyY });
  const msgHash = sha256(new TextEncoder().encode(nonce));
  const sigForVerify = sigDecoded.toDERRawBytes();
  const isValid = p256.verify(sigForVerify, msgHash, pubkey.toRawBytes());
  if (!isValid) {
    throw new InputError("INVALID_SIGNATURE", "Device signature verification failed");
  }

  const claimValues = buildClaimValues(params, options);
  const policyInputs = buildShowPolicyPublicInputs(params, nonce, options);

  return {
    deviceKeyX,
    deviceKeyY,
    sig_r: sigDecoded.r,
    sig_s_inverse: sigSInverse,
    messageHash: policyInputs.messageHash,
    predicateLen: policyInputs.predicateLen,
    claimValues,
    predicateClaimRefs: policyInputs.predicateClaimRefs,
    predicateOps: policyInputs.predicateOps,
    predicateRhsIsRef: policyInputs.predicateRhsIsRef,
    predicateRhsValues: policyInputs.predicateRhsValues,
    tokenTypes: policyInputs.tokenTypes,
    tokenValues: policyInputs.tokenValues,
    exprLen: policyInputs.exprLen,
  };
}

export function buildShowPolicyPublicInputs(
  params: ShowCircuitParams,
  nonce: string,
  options: ShowInputOptions = {},
): ShowPolicyPublicInputs {
  const messageHash = sha256(new TextEncoder().encode(nonce));
  const messageHashBigInt = bytesToBigInt(messageHash);
  const messageHashModQ = messageHashBigInt % P256_SCALAR_ORDER;
  const claimValues = buildClaimValues(params, options);
  const policy = buildPolicyInputs(params, claimValues, options);
  return {
    messageHash: messageHashModQ,
    ...policy,
  };
}

export function buildShowPolicyPublicValues(
  params: ShowCircuitParams,
  nonce: string,
  options: ShowInputOptions = {},
): bigint[] {
  const inputs = buildShowPolicyPublicInputs(params, nonce, options);
  return [
    inputs.messageHash,
    inputs.predicateLen,
    ...inputs.predicateClaimRefs,
    ...inputs.predicateOps,
    ...inputs.predicateRhsIsRef,
    ...inputs.predicateRhsValues,
    ...inputs.tokenTypes,
    ...inputs.tokenValues,
    inputs.exprLen,
  ];
}

export function showPolicyPublicValueCount(params: ShowCircuitParams): number {
  return 1 + 1 + params.maxPredicates * 4 + params.maxLogicTokens * 2 + 1;
}

export function buildPreparedMultiVerifierNonce(
  request: PreparedMultiChallengeRequest,
): string {
  const payload = {
    version: "openac-prepared-multi-v1",
    nonce: request.nonce,
    credentialCount: request.credentialCount,
    claimsPerCredential: request.claimsPerCredential,
    showParams: request.showParams,
    showPolicy: canonicalShowInputOptions(request.showInputOptions),
    keySetId: request.keySetId ?? "",
  };
  const json = JSON.stringify(payload);
  return `openac-prepared-multi-v1.${base64urlEncode(sha256HashString(json))}`;
}

function buildClaimValues(
  params: ShowCircuitParams,
  options: ShowInputOptions,
): bigint[] {
  const normalizedValues = options.normalizedClaimValues ?? [0n];
  const claimValues: bigint[] = Array(params.nClaims).fill(0n);
  for (let i = 0; i < Math.min(params.nClaims, normalizedValues.length); i++) {
    claimValues[i] = normalizedValues[i]!;
  }
  return claimValues;
}

function buildPolicyInputs(
  params: ShowCircuitParams,
  claimValues: bigint[],
  options: ShowInputOptions,
): Omit<ShowPolicyPublicInputs, "messageHash"> {
  const predicates = options.predicates ?? [
    { claimRef: 0, op: PredicateOp.EQ, rhsValue: claimValues[0]! },
  ];
  if (predicates.length > params.maxPredicates) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Predicate count (${predicates.length}) exceeds maxPredicates (${params.maxPredicates})`,
    );
  }
  const predicateLen = BigInt(predicates.length);

  const predicateClaimRefs: bigint[] = Array(params.maxPredicates).fill(0n);
  const predicateOps: bigint[] = Array(params.maxPredicates).fill(BigInt(PredicateOp.EQ));
  const predicateRhsIsRef: bigint[] = Array(params.maxPredicates).fill(0n);
  const predicateRhsValues: bigint[] = Array(params.maxPredicates).fill(claimValues[0] ?? 0n);

  for (let i = 0; i < predicates.length; i++) {
    const predicate = predicates[i]!;
    if (predicate.claimRef < 0 || predicate.claimRef >= params.nClaims) {
      throw new InputError(
        "PARAMS_EXCEEDED",
        `Predicate ${i} claimRef (${predicate.claimRef}) is outside nClaims (${params.nClaims})`,
      );
    }

    const rhsValue = predicate.rhsValue ?? predicate.compareValue;
    if (rhsValue === undefined) {
      throw new InputError(
        "PARAMS_EXCEEDED",
        `Predicate ${i} must provide rhsValue`,
      );
    }

    const rhsIsRef = predicate.rhsIsRef === true;
    if (rhsIsRef) {
      const rhsRef = Number(rhsValue);
      if (!Number.isSafeInteger(rhsRef) || rhsRef < 0 || rhsRef >= params.nClaims) {
        throw new InputError(
          "PARAMS_EXCEEDED",
          `Predicate ${i} RHS claim reference (${rhsValue}) is outside nClaims (${params.nClaims})`,
        );
      }
    }

    predicateClaimRefs[i] = BigInt(predicate.claimRef);
    predicateOps[i] = BigInt(predicate.op);
    predicateRhsIsRef[i] = rhsIsRef ? 1n : 0n;
    predicateRhsValues[i] = rhsValue;
  }

  const logicExpr = options.logicExpression ?? [{ type: LogicToken.REF, value: 0 }];
  const exprLen = BigInt(logicExpr.length);

  if (logicExpr.length > params.maxLogicTokens) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Logic expression length (${logicExpr.length}) exceeds maxLogicTokens (${params.maxLogicTokens})`,
    );
  }

  const tokenTypes: bigint[] = Array(params.maxLogicTokens).fill(0n);
  const tokenValues: bigint[] = Array(params.maxLogicTokens).fill(0n);

  for (let i = 0; i < logicExpr.length; i++) {
    tokenTypes[i] = BigInt(logicExpr[i]!.type);
    tokenValues[i] = BigInt(logicExpr[i]!.value);
  }

  return {
    predicateLen,
    predicateClaimRefs,
    predicateOps,
    predicateRhsIsRef,
    predicateRhsValues,
    tokenTypes,
    tokenValues,
    exprLen,
  };
}

function canonicalShowInputOptions(options: ShowInputOptions): object {
  return {
    predicates: (options.predicates ?? []).map((predicate) => ({
      claimRef: predicate.claimRef,
      op: predicate.op,
      rhsIsRef: predicate.rhsIsRef === true,
      rhsValue: (predicate.rhsValue ?? predicate.compareValue)?.toString() ?? "",
    })),
    logicExpression: (options.logicExpression ?? []).map((token) => ({
      type: token.type,
      value: token.value,
    })),
  };
}

function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function base64Decode(input: string): Uint8Array {
  // handle base64url
  let b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (b64.length % 4)) % 4;
  b64 += "=".repeat(pad);

  const binStr = atob(b64);
  const bytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) {
    bytes[i] = binStr.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64url(bytes: Uint8Array): string {
  const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let result = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = bytes[i + 1] ?? 0;
    const c = bytes[i + 2] ?? 0;
    const triplet = (a << 16) | (b << 8) | c;
    result += B64_CHARS[(triplet >> 18) & 0x3f];
    result += B64_CHARS[(triplet >> 12) & 0x3f];
    result += i + 1 < bytes.length ? B64_CHARS[(triplet >> 6) & 0x3f]! : "";
    result += i + 2 < bytes.length ? B64_CHARS[triplet & 0x3f]! : "";
  }
  return result.replace(/\+/g, "-").replace(/\//g, "_");
}

import * as fs from "fs";
import * as path from "path";
import * as nodeCrypto from "crypto";

import { generateMockData } from "./mock-vc-generator";
import { generateShowCircuitParams, generateShowInputs, signDeviceNonce } from "./show";
import { PredicateFormat } from "./predicate-types";

export const CIRCUIT_SIZES: Record<string, number[]> = {
  // "default" matches the params baked into circuits/main/{jwt,show}.circom and writes
  // to inputs/{jwt,show}/default.json (not a sized subfolder).
  default: [1920, 1900, 4, 50, 128],
  "1k": [1280, 960, 4, 50, 128],
  "2k": [2048, 2000, 4, 50, 128],
  "4k": [4096, 4000, 4, 50, 128],
  "8k": [8192, 8000, 4, 50, 128],
};

// Predicate operator codes (see eval-predicate.circom).
const OP_LE = 0;
const OP_GE = 1;
const LOGIC_REF = 0;
const LOGIC_AND = 1;

const FILL_RATIO = 0.8;

async function generateInputsForSize(sizeName: string): Promise<void> {
  const params = CIRCUIT_SIZES[sizeName];
  if (!params) {
    throw new Error(`Unknown size '${sizeName}'. Valid sizes: ${Object.keys(CIRCUIT_SIZES).join(", ")}`);
  }

  const [maxMessageLength, maxB64PayloadLength, maxMatches, maxSubstringLength, maxClaimsLength] = params;
  const targetPayloadLength = Math.floor(maxB64PayloadLength * FILL_RATIO);

  console.log(`\n[${sizeName}] Generating inputs...`);
  console.log(`  Circuit params : [${params.join(", ")}]`);
  console.log(
    `  Target payload : ${targetPayloadLength} / ${maxB64PayloadLength} chars (${Math.round(FILL_RATIO * 100)}% fill)`,
  );

  // Default mock claims are [name, roc_birthday]; mark roc_birthday as a ROC date so the
  // JWT circuit normalizes it to a comparable integer that the Show circuit can predicate over.
  const claimFormats = [PredicateFormat.STRING_EQ, PredicateFormat.ROC_DATE];

  const mockData = await generateMockData({
    circuitParams: params,
    targetPayloadLength,
    claimFormats,
  });

  const actualPayloadLen = mockData.token.split(".")[1].length;
  console.log(
    `  Actual payload : ${actualPayloadLen} chars (${((actualPayloadLen / maxB64PayloadLength) * 100).toFixed(1)}% fill)`,
  );

  const showParams = generateShowCircuitParams(params);

  const rocBirthdayClaim = mockData.claims[1];
  if (!rocBirthdayClaim) {
    throw new Error(`Expected mock data to include a roc_birthday claim at index 1`);
  }

  const nonce = nodeCrypto.randomBytes(24).toString("base64url");
  const deviceSignature = signDeviceNonce(nonce, mockData.devicePrivateKey);

  // Show predicate: claim[0] (roc_birthday) <= 1070101 (ROC adult cutoff).
  const showInputs = generateShowInputs(
    showParams,
    nonce,
    deviceSignature,
    mockData.deviceKey,
    [rocBirthdayClaim],
  );
  showInputs.predicateLen = 1n;
  showInputs.predicateClaimRefs[0] = 0n;
  showInputs.predicateOps[0] = BigInt(OP_LE);
  showInputs.predicateRhsValues[0] = 1070101n;
  showInputs.tokenTypes[0] = 0n;
  showInputs.tokenValues[0] = 0n;
  showInputs.exprLen = 1n;

  const circomDir = path.resolve(__dirname, "..");
  // The "default" pseudo-size writes to inputs/{jwt,show}/default.json directly,
  // matching the params in circuits/main/{jwt,show}.circom.
  const isDefault = sizeName === "default";
  const jwtOutputDir = isDefault ? path.join(circomDir, "inputs", "jwt") : path.join(circomDir, "inputs", "jwt", sizeName);
  const showOutputDir = isDefault ? path.join(circomDir, "inputs", "show") : path.join(circomDir, "inputs", "show", sizeName);

  fs.mkdirSync(jwtOutputDir, { recursive: true });
  fs.mkdirSync(showOutputDir, { recursive: true });

  const jwtOutputPath = path.join(jwtOutputDir, "default.json");
  const showOutputPath = path.join(showOutputDir, "default.json");

  const bigintReplacer = (_key: string, value: any) => (typeof value === "bigint" ? value.toString() : value);

  fs.writeFileSync(jwtOutputPath, JSON.stringify(mockData.circuitInputs, bigintReplacer, 2));
  fs.writeFileSync(showOutputPath, JSON.stringify(showInputs, bigintReplacer, 2));

  console.log(`  JWT  inputs → ${path.relative(circomDir, jwtOutputPath)}`);
  console.log(`  Show inputs → ${path.relative(circomDir, showOutputPath)}`);

  // Option 2 / Track A fixture: two credentials bound to the same device key.
  const secondClaimFormats = [PredicateFormat.STRING_EQ, PredicateFormat.UINT];
  const mockData2 = await generateMockData({
    circuitParams: params,
    targetPayloadLength,
    claimFormats: secondClaimFormats,
    claims: [
      { key: "membership", value: "GOLD" },
      { key: "balance", value: "12000" },
    ],
    devicePrivateKey: mockData.devicePrivateKey,
    deviceKey: mockData.deviceKey,
    kid: "key-2",
  });

  const prepare2vcOutputDir = isDefault
    ? path.join(circomDir, "inputs", "prepare_2vc")
    : path.join(circomDir, "inputs", "prepare_2vc", sizeName);
  const show2vcOutputDir = isDefault
    ? path.join(circomDir, "inputs", "show_2vc")
    : path.join(circomDir, "inputs", "show_2vc", sizeName);
  fs.mkdirSync(prepare2vcOutputDir, { recursive: true });
  fs.mkdirSync(show2vcOutputDir, { recursive: true });

  const prepare2vcInputs = {
    vc0: mockData.circuitInputs,
    vc1: mockData2.circuitInputs,
  };

  const show2vcParams = {
    nClaims: showParams.nClaims * 2,
    maxPredicates: showParams.maxPredicates,
    maxLogicTokens: showParams.maxLogicTokens,
    valueBits: showParams.valueBits,
  };

  const show2vcInputs = generateShowInputs(
    show2vcParams,
    nonce,
    deviceSignature,
    mockData.deviceKey,
    [...mockData.claims, ...mockData2.claims],
  );

  // pred0: VC0 roc_birthday <= adult cutoff
  show2vcInputs.predicateLen = 2n;
  show2vcInputs.predicateClaimRefs[0] = 1n;
  show2vcInputs.predicateOps[0] = BigInt(OP_LE);
  show2vcInputs.predicateRhsValues[0] = 1070101n;

  // pred1: VC1 balance >= 10000
  show2vcInputs.predicateClaimRefs[1] = 3n;
  show2vcInputs.predicateOps[1] = BigInt(OP_GE);
  show2vcInputs.predicateRhsValues[1] = 10000n;

  // pred0 AND pred1
  show2vcInputs.tokenTypes[0] = BigInt(LOGIC_REF);
  show2vcInputs.tokenValues[0] = 0n;
  show2vcInputs.tokenTypes[1] = BigInt(LOGIC_REF);
  show2vcInputs.tokenValues[1] = 1n;
  show2vcInputs.tokenTypes[2] = BigInt(LOGIC_AND);
  show2vcInputs.tokenValues[2] = 0n;
  show2vcInputs.exprLen = 3n;

  const prepare2vcOutputPath = path.join(prepare2vcOutputDir, "default.json");
  const show2vcOutputPath = path.join(show2vcOutputDir, "default.json");
  fs.writeFileSync(prepare2vcOutputPath, JSON.stringify(prepare2vcInputs, bigintReplacer, 2));
  fs.writeFileSync(show2vcOutputPath, JSON.stringify(show2vcInputs, bigintReplacer, 2));

  console.log(`  Prepare2VC inputs → ${path.relative(circomDir, prepare2vcOutputPath)}`);
  console.log(`  Show2VC inputs    → ${path.relative(circomDir, show2vcOutputPath)}`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    console.log(`
Usage: npx ts-node src/generate-inputs.ts [options]

Options:
  --size <size>  Generate single-VC and 2VC inputs for a size (default | 1k | 2k | 4k | 8k)
  --all          Generate single-VC and 2VC inputs for all sizes
  -h, --help     Show this help message

Examples:
  npx ts-node src/generate-inputs.ts --size 2k
  npx ts-node src/generate-inputs.ts --all
`);
    process.exit(0);
  }

  if (args.includes("--all")) {
    for (const sizeName of Object.keys(CIRCUIT_SIZES)) {
      await generateInputsForSize(sizeName);
    }
    console.log("\nAll inputs generated successfully.");
    return;
  }

  const sizeIdx = args.indexOf("--size");
  if (sizeIdx === -1 || !args[sizeIdx + 1]) {
    console.error("Error: --size <size> is required (or use --all).");
    process.exit(1);
  }

  const sizeName = args[sizeIdx + 1];
  await generateInputsForSize(sizeName);
  console.log("\nDone.");
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});

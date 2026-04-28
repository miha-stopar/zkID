import assert from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { generateMockData } from "../../src/mock-vc-generator.ts";
import { PredicateFormat } from "../../src/predicate-types.ts";
import { base64ToBigInt, base64urlToBase64 } from "../../src/utils.ts";

type JwtCircuitInputs = Record<string, any>;

const ARRAY_FIELDS = [
  "message",
  "messageLength",
  "periodIndex",
  "sig_r",
  "sig_s_inverse",
  "pubKeyX",
  "pubKeyY",
  "matchesCount",
  "matchSubstring",
  "matchLength",
  "matchIndex",
  "claims",
  "claimLengths",
  "decodeFlags",
  "claimFormats",
] as const;

function mergePrepareNVcInputs(credentials: JwtCircuitInputs[]) {
  return Object.fromEntries(
    ARRAY_FIELDS.map((field) => [
      field,
      credentials.map((credential) => credential[field]),
    ]),
  );
}

describe("PrepareNSdJwt Circuit", () => {
  let circuit: WitnessTester<any, any>;

  before(async () => {
    circuit = await circomkit.WitnessTester("PrepareNSdJwt3", {
      file: "prepare_nsdjwt",
      template: "PrepareNSdJwt",
      params: [3, 1280, 960, 4, 50, 128],
      recompile: true,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("verifies three SD-JWTs bound to the same device key", async () => {
    const circuitParams = [1280, 960, 4, 50, 128];
    const vc0 = await generateMockData({
      circuitParams,
      claimFormats: [PredicateFormat.STRING_EQ, PredicateFormat.ROC_DATE],
    });
    const vc1 = await generateMockData({
      circuitParams,
      claims: [
        { key: "membership", value: "GOLD" },
        { key: "balance", value: "12000" },
      ],
      claimFormats: [PredicateFormat.STRING_EQ, PredicateFormat.UINT],
      kid: "key-2",
      devicePrivateKey: vc0.devicePrivateKey,
      deviceKey: vc0.deviceKey,
    });
    const vc2 = await generateMockData({
      circuitParams,
      claims: [
        { key: "membership", value: "GOLD" },
        { key: "balance", value: "12000" },
      ],
      claimFormats: [PredicateFormat.STRING_EQ, PredicateFormat.UINT],
      kid: "key-2",
      devicePrivateKey: vc0.devicePrivateKey,
      deviceKey: vc0.deviceKey,
    });

    const inputs = mergePrepareNVcInputs([
      vc0.circuitInputs,
      vc1.circuitInputs,
      vc2.circuitInputs,
    ]);
    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);

    const deviceKeyX = base64ToBigInt(base64urlToBase64(vc0.deviceKey.x));
    const deviceKeyY = base64ToBigInt(base64urlToBase64(vc0.deviceKey.y));
    assert.strictEqual(witness[7], deviceKeyX);
    assert.strictEqual(witness[8], deviceKeyY);
  });

  it("rejects credentials bound to different device keys", async () => {
    const circuitParams = [1280, 960, 4, 50, 128];
    const vc0 = await generateMockData({
      circuitParams,
      claimFormats: [PredicateFormat.STRING_EQ, PredicateFormat.ROC_DATE],
    });
    const vc1 = await generateMockData({
      circuitParams,
      claims: [
        { key: "membership", value: "GOLD" },
        { key: "balance", value: "12000" },
      ],
      claimFormats: [PredicateFormat.STRING_EQ, PredicateFormat.UINT],
      kid: "key-2",
      devicePrivateKey: vc0.devicePrivateKey,
      deviceKey: vc0.deviceKey,
    });
    const vc2 = await generateMockData({
      circuitParams,
      claims: [
        { key: "role", value: "ADMIN" },
        { key: "score", value: "77" },
      ],
      claimFormats: [PredicateFormat.STRING_EQ, PredicateFormat.UINT],
      kid: "key-3",
    });

    const inputs = mergePrepareNVcInputs([
      vc0.circuitInputs,
      vc1.circuitInputs,
      vc2.circuitInputs,
    ]);

    await assert.rejects(async () => {
      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);
    });
  });
});

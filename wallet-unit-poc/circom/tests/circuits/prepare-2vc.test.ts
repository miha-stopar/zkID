import assert from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { generateMockData } from "../../src/mock-vc-generator.ts";
import { PredicateFormat } from "../../src/predicate-types.ts";
import { base64ToBigInt, base64urlToBase64 } from "../../src/utils.ts";

type Prepare2VcInputs = Record<string, any>;

function prefixInputs(inputs: Record<string, unknown>, suffix: "0" | "1"): Prepare2VcInputs {
  return Object.fromEntries(Object.entries(inputs).map(([key, value]) => [`${key}${suffix}`, value]));
}

function mergePrepare2VcInputs(vc0: Record<string, unknown>, vc1: Record<string, unknown>): Prepare2VcInputs {
  return {
    ...prefixInputs(vc0, "0"),
    ...prefixInputs(vc1, "1"),
  };
}

describe("Prepare2SdJwt Circuit", () => {
  let circuit: WitnessTester<any, any>;

  before(async () => {
    circuit = await circomkit.WitnessTester("Prepare2SdJwt", {
      file: "prepare_2sdjwt",
      template: "Prepare2SdJwt",
      params: [1280, 960, 4, 50, 128],
      recompile: true,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("verifies two SD-JWTs bound to the same device key", async () => {
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

    const inputs = mergePrepare2VcInputs(vc0.circuitInputs, vc1.circuitInputs);
    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);

    const deviceKeyX = base64ToBigInt(base64urlToBase64(vc0.deviceKey.x));
    const deviceKeyY = base64ToBigInt(base64urlToBase64(vc0.deviceKey.y));
    assert.strictEqual(witness[5], deviceKeyX);
    assert.strictEqual(witness[6], deviceKeyY);
  });

  it("rejects two SD-JWTs bound to different device keys", async () => {
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
    });

    const inputs = mergePrepare2VcInputs(vc0.circuitInputs, vc1.circuitInputs);
    await assert.rejects(async () => {
      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);
    });
  });
});

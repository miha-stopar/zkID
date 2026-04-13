import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { generateMockData } from "../../src/mock-vc-generator.ts";
import { generateJwtCircuitParams, generateJwtInputs } from "../../src/jwt.ts";
import { PredicateFormat } from "../../src/predicate-types.ts";

describe("JWT Circuit - Claim Value Normalization", () => {
  let circuit: WitnessTester<any, any>;

  before(async () => {
    const RECOMPILE = true;
    circuit = await circomkit.WitnessTester(`JWT`, {
      file: "jwt",
      template: "JWT",
      params: [2048, 2000, 6, 50, 128],
      recompile: RECOMPILE,
    });
    console.log("JWT circuit constraints:", await circuit.getConstraintCount());
  });

  it("should produce a valid witness for a roc_date claim", async () => {
    // roc_birthday = "0570605" should be normalized to 570605 via roc_date format.
    const mockData = await generateMockData({
      circuitParams: [2048, 2000, 6, 50, 128],
      claims: [
        { key: "name", value: "Charlie" },
        { key: "roc_birthday", value: "0570605" },
      ],
    });

    const params = generateJwtCircuitParams([2048, 2000, 6, 50, 128]);
    const inputs = generateJwtInputs(
      params,
      mockData.token,
      mockData.issuerKey,
      mockData.hashedClaims,
      mockData.claims,
      [PredicateFormat.STRING_EQ, PredicateFormat.ROC_DATE]
    );

    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);
  });

  it("should produce a valid witness when normalizing multiple claims with different formats", async () => {
    // roc_birthday → roc_date format; name → string format.
    const mockData = await generateMockData({
      circuitParams: [2048, 2000, 6, 50, 128],
      claims: [
        { key: "roc_birthday", value: "0570605" },
        { key: "name", value: "Charlie" },
      ],
    });

    const params = generateJwtCircuitParams([2048, 2000, 6, 50, 128]);
    const inputs = generateJwtInputs(
      params,
      mockData.token,
      mockData.issuerKey,
      mockData.hashedClaims,
      mockData.claims,
      [PredicateFormat.ROC_DATE, PredicateFormat.STRING_EQ]
    );

    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);
  });

  it("should produce a valid witness when some claim slots are unused", async () => {
    // Only 2 claims for a 6-slot circuit; remaining slots should normalize to 0.
    const mockData = await generateMockData({
      circuitParams: [2048, 2000, 6, 50, 128],
      claims: [
        { key: "name", value: "Charlie" },
        { key: "roc_birthday", value: "0570605" },
      ],
    });

    const params = generateJwtCircuitParams([2048, 2000, 6, 50, 128]);
    const inputs = generateJwtInputs(
      params,
      mockData.token,
      mockData.issuerKey,
      mockData.hashedClaims,
      mockData.claims,
      [PredicateFormat.STRING_EQ, PredicateFormat.ROC_DATE]
    );

    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);
  });

  it("should produce a valid witness for a string claim", async () => {
    // name = "Charlie" should be packed big-endian into a single field element.
    const mockData = await generateMockData({
      circuitParams: [2048, 2000, 6, 50, 128],
      claims: [
        { key: "name", value: "Charlie" },
      ],
    });

    const params = generateJwtCircuitParams([2048, 2000, 6, 50, 128]);
    const inputs = generateJwtInputs(
      params,
      mockData.token,
      mockData.issuerKey,
      mockData.hashedClaims,
      mockData.claims,
      [PredicateFormat.STRING_EQ]
    );

    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);
  });
});

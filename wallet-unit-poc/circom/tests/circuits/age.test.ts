import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { assert } from "console";

describe("AgeVerifier (ROC)", () => {
  let circuit: WitnessTester<["claim", "currentYear", "currentMonth", "currentDay"], ["ageAbove18"]>;

  const maxClaimLength = 128;
  const byteLength = Math.floor((maxClaimLength * 3) / 4);

  before(async () => {
    circuit = await circomkit.WitnessTester("AgeVerifier", {
      file: "components/age-verifier",
      template: "AgeVerifier",
      params: [byteLength],
      recompile: true,
    });
    console.log("AgeVerifier constraints:", await circuit.getConstraintCount());
  });

  it("should decode ROC claims and pass constraints", async () => {
    const input = "WyJGc2w4ZWpObEFNT2Vqc1lTdjc2Z1NnIiwicm9jX2JpcnRoZGF5IiwiMTA0MDYwNSJd";

    let decodedClaims = Array.from(Buffer.from(atob(input)));
    while (decodedClaims.length < byteLength) {
      decodedClaims.push(0);
    }

    const now = new Date();
    const currentYear = BigInt(now.getUTCFullYear());
    const currentMonth = BigInt(now.getUTCMonth() + 1);
    const currentDay = BigInt(now.getUTCDate());

    const witness = await circuit.calculateWitness({
      claim: decodedClaims,
      currentYear,
      currentMonth,
      currentDay,
    });

    await circuit.expectConstraintPass(witness);
  });
});

describe("AgeVerifierISO (ISO 8601)", () => {
  let circuit: WitnessTester<["claim", "currentYear", "currentMonth", "currentDay"], ["ageAbove18"]>;

  const maxClaimLength = 128;
  const byteLength = Math.floor((maxClaimLength * 3) / 4);

  before(async () => {
    circuit = await circomkit.WitnessTester("AgeVerifierISO", {
      file: "components/age-verifier",
      template: "AgeVerifierISO",
      params: [byteLength],
      recompile: true,
    });
    console.log("AgeVerifierISO constraints:", await circuit.getConstraintCount());
  });

  it("should verify age above 18 with ISO 8601 format", async () => {
    const jsonStr = '["Fsl8ejNlAMOejsYSv76gSg","birthday","1968-06-05"]';
    let decodedClaims = Array.from(Buffer.from(jsonStr));
    while (decodedClaims.length < byteLength) {
      decodedClaims.push(0);
    }

    const witness = await circuit.calculateWitness({
      claim: decodedClaims,
      currentYear: BigInt(2025),
      currentMonth: BigInt(3),
      currentDay: BigInt(15),
    });
    await circuit.expectConstraintPass(witness);
    const signals = await circuit.readWitnessSignals(witness, ["ageAbove18"]);
    assert(signals.ageAbove18 === 1n, `Expected ageAbove18=1, got ${signals.ageAbove18}`);
  });

  it("should verify age below 18 with ISO 8601 format", async () => {
    const jsonStr = '["Fsl8ejNlAMOejsYSv76gSg","birthday","2015-06-05"]';
    let decodedClaims = Array.from(Buffer.from(jsonStr));
    while (decodedClaims.length < byteLength) {
      decodedClaims.push(0);
    }

    const witness = await circuit.calculateWitness({
      claim: decodedClaims,
      currentYear: BigInt(2025),
      currentMonth: BigInt(3),
      currentDay: BigInt(15),
    });
    await circuit.expectConstraintPass(witness);
    const signals = await circuit.readWitnessSignals(witness, ["ageAbove18"]);
    assert(signals.ageAbove18 === 0n, `Expected ageAbove18=0, got ${signals.ageAbove18}`);
  });
});

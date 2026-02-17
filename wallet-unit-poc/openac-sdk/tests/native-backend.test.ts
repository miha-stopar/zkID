import { describe, it, expect, beforeAll } from "vitest";
import { existsSync } from "fs";
import { readFile } from "fs/promises";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { WitnessCalculator } from "../src/witness-calculator.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const KEYS_DIR = join(__dirname, "..", "..", "ecdsa-spartan2", "keys");
const ASSETS_DIR = join(__dirname, "..", "assets");
const INPUTS_DIR = join(__dirname, "..", "..", "circom", "inputs");

describe("Native Backend — Artifact Existence", () => {
  it("should find pre-generated keys directory", () => {
    expect(existsSync(KEYS_DIR)).toBe(true);
  });

  it("should have prepare verifying key", () => {
    const vkPath = join(KEYS_DIR, "prepare_verifying.key");
    expect(existsSync(vkPath)).toBe(true);
  });

  it("should have show verifying key", () => {
    const vkPath = join(KEYS_DIR, "show_verifying.key");
    expect(existsSync(vkPath)).toBe(true);
  });

  it("should have prepare proof artifact", () => {
    const proofPath = join(KEYS_DIR, "prepare_proof.bin");
    expect(existsSync(proofPath)).toBe(true);
  });

  it("should have show proof artifact", () => {
    const proofPath = join(KEYS_DIR, "show_proof.bin");
    expect(existsSync(proofPath)).toBe(true);
  });

  it("should have shared blinds", () => {
    const blindsPath = join(KEYS_DIR, "shared_blinds.bin");
    expect(existsSync(blindsPath)).toBe(true);
  });

  it("should have all proof components", () => {
    const artifacts = [
      "prepare_proof.bin",
      "show_proof.bin",
      "prepare_instance.bin",
      "show_instance.bin",
      "prepare_witness.bin",
      "show_witness.bin",
      "shared_blinds.bin",
    ];

    for (const artifact of artifacts) {
      const path = join(KEYS_DIR, artifact);
      expect(existsSync(path), `${artifact} should exist`).toBe(true);
    }
  });
});

describe("Age Verification", () => {
  let calculator: WitnessCalculator;

  beforeAll(async () => {
    calculator = new WitnessCalculator(ASSETS_DIR);
    await calculator.init();
  });

  it("should verify age from Show circuit witness", async () => {
    const inputJson = JSON.parse(
      await readFile(join(INPUTS_DIR, "show", "default.json"), "utf-8"),
    );

    const inputs: Record<string, unknown> = {
      deviceKeyX: BigInt(inputJson.deviceKeyX),
      deviceKeyY: BigInt(inputJson.deviceKeyY),
      sig_r: BigInt(inputJson.sig_r),
      sig_s_inverse: BigInt(inputJson.sig_s_inverse),
      messageHash: BigInt(inputJson.messageHash),
      claim: inputJson.claim.map((v: string) => BigInt(v)),
      currentYear: BigInt(inputJson.currentYear),
      currentMonth: BigInt(inputJson.currentMonth),
      currentDay: BigInt(inputJson.currentDay),
    };

    const witness = await calculator.calculateShowWitness(inputs);

    expect(witness[1]).toBe(0n);
  }, 30_000);
});

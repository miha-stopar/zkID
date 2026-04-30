import { existsSync } from "fs";
import { readFile } from "fs/promises";
import { join, dirname } from "path";
import { fileURLToPath, pathToFileURL } from "url";
import { ProofError } from "./errors.js";
import {
  getPreparedMultiShowCircuitProfile,
} from "./multi-circuit.js";
import type {
  JwtCircuitInputs,
  JwtCircuitParams,
  ShowCircuitInputs,
} from "./types.js";

// Circom witness calculators accept any object with string keys
type CircuitInput = Record<string, unknown>;

interface WitnessCalculatorInstance {
  calculateWitness(input: CircuitInput, sanityCheck?: boolean): Promise<bigint[]>;
  calculateBinWitness(input: CircuitInput, sanityCheck?: boolean): Promise<Uint8Array>;
  calculateWTNSBin(input: CircuitInput, sanityCheck?: boolean): Promise<Uint8Array>;
}

type WitnessCalculatorBuilder = (
  code: ArrayBuffer | Uint8Array,
  options?: { sanityCheck?: boolean }
) => Promise<WitnessCalculatorInstance>;

export class WitnessCalculator {
  private jwtCalculators = new Map<string, WitnessCalculatorInstance>();
  private showCalculator: WitnessCalculatorInstance | null = null;
  private showMultiCalculators = new Map<number, WitnessCalculatorInstance>();
  private linkMultiCalculators = new Map<number, WitnessCalculatorInstance>();
  private builder: WitnessCalculatorBuilder | null = null;

  private showWasmPath: string;
  private assetsDir: string;

  constructor(assetsDir?: string) {
    const defaultAssetsDir = join(dirname(fileURLToPath(import.meta.url)), "..", "assets");
    this.assetsDir = assetsDir ?? defaultAssetsDir;
    this.showWasmPath = join(this.assetsDir, "show.wasm");
  }

  async init(): Promise<void> {
    const builderPath = join(dirname(fileURLToPath(import.meta.url)), "..", "assets", "witness_calculator.js");
    this.builder = await this.loadBuilder(builderPath);
  }

  private async loadCalculator(wasmPath: string): Promise<WitnessCalculatorInstance> {
    if (!this.builder) {
      throw new ProofError("WITNESS_GENERATION_FAILED", "Witness calculator not initialized. Call init() first.");
    }
    const wasmBuffer = await readFile(wasmPath);
    return await this.builder(wasmBuffer, { sanityCheck: true });
  }

  private async loadBuilder(builderPath: string): Promise<WitnessCalculatorBuilder> {
    try {
      const module = await import(/* webpackIgnore: true */ pathToFileURL(builderPath).href);
      return this.asBuilder(module.default ?? module);
    } catch (error) {
      const source = await readFile(builderPath, "utf8");
      const module = { exports: {} };
      // Circom emits this builder as CommonJS even when the SDK package is ESM.
      const evaluate = new Function("module", "exports", source);
      evaluate(module, module.exports);
      return this.asBuilder(module.exports);
    }
  }

  private asBuilder(value: unknown): WitnessCalculatorBuilder {
    if (typeof value !== "function") {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "Witness calculator builder did not export a function.",
      );
    }
    return value as WitnessCalculatorBuilder;
  }

  async calculateJwtWitness(
    inputs: JwtCircuitInputs | CircuitInput,
    params?: JwtCircuitParams,
  ): Promise<bigint[]> {
    const calculator = await this.getJwtCalculator(params);
    return await calculator.calculateWitness(inputs as CircuitInput, true);
  }

  async calculateShowWitness(inputs: ShowCircuitInputs | CircuitInput): Promise<bigint[]> {
    if (!this.showCalculator) {
      this.showCalculator = await this.loadCalculator(this.showWasmPath);
    }
    return await this.showCalculator.calculateWitness(inputs as CircuitInput, true);
  }

  async calculateShow2VcWitness(inputs: ShowCircuitInputs | CircuitInput): Promise<bigint[]> {
    return this.calculateShowMultiWitness(2, inputs);
  }

  async calculateShowMultiWitness(
    credentialCount: number,
    inputs: ShowCircuitInputs | CircuitInput,
  ): Promise<bigint[]> {
    const calculator = await this.getShowMultiCalculator(credentialCount);
    return await calculator.calculateWitness(inputs as CircuitInput, true);
  }

  async calculateJwtWitnessWtns(
    inputs: JwtCircuitInputs | CircuitInput,
    params?: JwtCircuitParams,
  ): Promise<Uint8Array> {
    const calculator = await this.getJwtCalculator(params);
    return await calculator.calculateWTNSBin(inputs as CircuitInput, true);
  }

  async calculateShowWitnessWtns(inputs: ShowCircuitInputs | CircuitInput): Promise<Uint8Array> {
    if (!this.showCalculator) {
      this.showCalculator = await this.loadCalculator(this.showWasmPath);
    }
    return await this.showCalculator.calculateWTNSBin(inputs as CircuitInput, true);
  }

  async calculateShow2VcWitnessWtns(inputs: ShowCircuitInputs | CircuitInput): Promise<Uint8Array> {
    return this.calculateShowMultiWitnessWtns(2, inputs);
  }

  async calculateShowMultiWitnessWtns(
    credentialCount: number,
    inputs: ShowCircuitInputs | CircuitInput,
  ): Promise<Uint8Array> {
    const calculator = await this.getShowMultiCalculator(credentialCount);
    return await calculator.calculateWTNSBin(inputs as CircuitInput, true);
  }

  async calculateLinkMultiWitness(
    credentialCount: number,
    inputs: CircuitInput,
  ): Promise<bigint[]> {
    const calculator = await this.getLinkMultiCalculator(credentialCount);
    return await calculator.calculateWitness(inputs, true);
  }

  async calculateLinkMultiWitnessWtns(
    credentialCount: number,
    inputs: CircuitInput,
  ): Promise<Uint8Array> {
    const calculator = await this.getLinkMultiCalculator(credentialCount);
    return await calculator.calculateWTNSBin(inputs, true);
  }

  private async getJwtCalculator(
    params?: JwtCircuitParams,
  ): Promise<WitnessCalculatorInstance> {
    const wasmPath = this.jwtWitnessWasmPath(params);
    const existing = this.jwtCalculators.get(wasmPath);
    if (existing) return existing;

    const calculator = await this.loadCalculator(wasmPath);
    this.jwtCalculators.set(wasmPath, calculator);
    return calculator;
  }

  private jwtWitnessWasmPath(params?: JwtCircuitParams): string {
    const name = jwtWitnessWasmName(params);
    const candidates = name === "jwt.wasm"
      ? [join(this.assetsDir, name)]
      : [
          join(this.assetsDir, name),
          join(this.assetsDir, name.replace(".wasm", ""), name),
        ];

    const existing = candidates.find((candidate) => existsSync(candidate));
    return existing ?? candidates[0]!;
  }

  private async getShowMultiCalculator(
    credentialCount: number,
  ): Promise<WitnessCalculatorInstance> {
    const existing = this.showMultiCalculators.get(credentialCount);
    if (existing) return existing;

    const profile = getPreparedMultiShowCircuitProfile(credentialCount);
    const calculator = await this.loadCalculator(
      join(this.assetsDir, profile.showWitnessWasm),
    );
    this.showMultiCalculators.set(credentialCount, calculator);
    return calculator;
  }

  private async getLinkMultiCalculator(
    credentialCount: number,
  ): Promise<WitnessCalculatorInstance> {
    const existing = this.linkMultiCalculators.get(credentialCount);
    if (existing) return existing;

    const profile = getPreparedMultiShowCircuitProfile(credentialCount);
    const calculator = await this.loadCalculator(
      join(this.assetsDir, profile.linkWitnessWasm),
    );
    this.linkMultiCalculators.set(credentialCount, calculator);
    return calculator;
  }
}

export function jwtWitnessWasmName(params?: JwtCircuitParams): string {
  if (!params) return "jwt.wasm";

  const key = [
    params.maxMessageLength,
    params.maxB64PayloadLength,
    params.maxMatches,
    params.maxSubstringLength,
    params.maxClaimLength,
  ].join(":");

  switch (key) {
    case "1280:960:4:50:128":
      return "jwt_1k.wasm";
    case "2048:2000:4:50:128":
      return "jwt_2k.wasm";
    case "4096:4000:4:50:128":
      return "jwt_4k.wasm";
    case "8192:8000:4:50:128":
      return "jwt_8k.wasm";
    default:
      return "jwt.wasm";
  }
}

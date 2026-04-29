import { readFile } from "fs/promises";
import { join, dirname } from "path";
import { fileURLToPath, pathToFileURL } from "url";
import { ProofError } from "./errors.js";
import {
  getMultiCredentialCircuitProfile,
  getPreparedMultiShowCircuitProfile,
} from "./multi-circuit.js";
import type { JwtCircuitInputs, Prepare2VcCircuitInputs, ShowCircuitInputs } from "./types.js";

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
  private jwtCalculator: WitnessCalculatorInstance | null = null;
  private showCalculator: WitnessCalculatorInstance | null = null;
  private prepareMultiCalculators = new Map<number, WitnessCalculatorInstance>();
  private showMultiCalculators = new Map<number, WitnessCalculatorInstance>();
  private builder: WitnessCalculatorBuilder | null = null;

  private jwtWasmPath: string;
  private showWasmPath: string;
  private assetsDir: string;

  constructor(assetsDir?: string) {
    const defaultAssetsDir = join(dirname(fileURLToPath(import.meta.url)), "..", "assets");
    this.assetsDir = assetsDir ?? defaultAssetsDir;
    this.jwtWasmPath = join(this.assetsDir, "jwt.wasm");
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

  async calculateJwtWitness(inputs: JwtCircuitInputs | CircuitInput): Promise<bigint[]> {
    if (!this.jwtCalculator) {
      this.jwtCalculator = await this.loadCalculator(this.jwtWasmPath);
    }
    return await this.jwtCalculator.calculateWitness(inputs as CircuitInput, true);
  }

  async calculateShowWitness(inputs: ShowCircuitInputs | CircuitInput): Promise<bigint[]> {
    if (!this.showCalculator) {
      this.showCalculator = await this.loadCalculator(this.showWasmPath);
    }
    return await this.showCalculator.calculateWitness(inputs as CircuitInput, true);
  }

  async calculatePrepare2VcWitness(inputs: Prepare2VcCircuitInputs | CircuitInput): Promise<bigint[]> {
    return this.calculatePrepareMultiWitness(2, inputs);
  }

  async calculateShow2VcWitness(inputs: ShowCircuitInputs | CircuitInput): Promise<bigint[]> {
    return this.calculateShowMultiWitness(2, inputs);
  }

  async calculatePrepareMultiWitness(
    credentialCount: number,
    inputs: Prepare2VcCircuitInputs | CircuitInput,
  ): Promise<bigint[]> {
    const calculator = await this.getPrepareMultiCalculator(credentialCount);
    return await calculator.calculateWitness(inputs as CircuitInput, true);
  }

  async calculateShowMultiWitness(
    credentialCount: number,
    inputs: ShowCircuitInputs | CircuitInput,
  ): Promise<bigint[]> {
    const calculator = await this.getShowMultiCalculator(credentialCount);
    return await calculator.calculateWitness(inputs as CircuitInput, true);
  }

  async calculateJwtWitnessWtns(inputs: JwtCircuitInputs | CircuitInput): Promise<Uint8Array> {
    if (!this.jwtCalculator) {
      this.jwtCalculator = await this.loadCalculator(this.jwtWasmPath);
    }
    return await this.jwtCalculator.calculateWTNSBin(inputs as CircuitInput, true);
  }

  async calculateShowWitnessWtns(inputs: ShowCircuitInputs | CircuitInput): Promise<Uint8Array> {
    if (!this.showCalculator) {
      this.showCalculator = await this.loadCalculator(this.showWasmPath);
    }
    return await this.showCalculator.calculateWTNSBin(inputs as CircuitInput, true);
  }

  async calculatePrepare2VcWitnessWtns(inputs: Prepare2VcCircuitInputs | CircuitInput): Promise<Uint8Array> {
    return this.calculatePrepareMultiWitnessWtns(2, inputs);
  }

  async calculateShow2VcWitnessWtns(inputs: ShowCircuitInputs | CircuitInput): Promise<Uint8Array> {
    return this.calculateShowMultiWitnessWtns(2, inputs);
  }

  async calculatePrepareMultiWitnessWtns(
    credentialCount: number,
    inputs: Prepare2VcCircuitInputs | CircuitInput,
  ): Promise<Uint8Array> {
    const calculator = await this.getPrepareMultiCalculator(credentialCount);
    return await calculator.calculateWTNSBin(inputs as CircuitInput, true);
  }

  async calculateShowMultiWitnessWtns(
    credentialCount: number,
    inputs: ShowCircuitInputs | CircuitInput,
  ): Promise<Uint8Array> {
    const calculator = await this.getShowMultiCalculator(credentialCount);
    return await calculator.calculateWTNSBin(inputs as CircuitInput, true);
  }

  private async getPrepareMultiCalculator(
    credentialCount: number,
  ): Promise<WitnessCalculatorInstance> {
    const existing = this.prepareMultiCalculators.get(credentialCount);
    if (existing) return existing;

    const profile = getMultiCredentialCircuitProfile(credentialCount);
    const calculator = await this.loadCalculator(
      join(this.assetsDir, profile.prepareWitnessWasm),
    );
    this.prepareMultiCalculators.set(credentialCount, calculator);
    return calculator;
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
}

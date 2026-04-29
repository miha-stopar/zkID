// Wraps the ecdsa-spartan2 Rust CLI binary for heavy operations
// (setup, prove, reblind) that are impractical in WASM due to 420MB key sizes.
// Node.js only.

import { execFile } from "child_process";
import { readFile, writeFile, mkdir } from "fs/promises";
import { join, dirname } from "path";
import { existsSync, readdirSync } from "fs";
import { promisify } from "util";
import { SetupError, ProofError } from "./errors.js";
import {
  getMultiCredentialCircuitProfile,
  getPreparedMultiShowCircuitProfile,
  jwtParamsForVcSize,
} from "./multi-circuit.js";
import type {
  KeySet,
  PreparedMultiKeySet,
  PreparedMultiVerifyingKeys,
  SerializedKeySet,
  SerializedPreparedMultiKeySet,
  VerifyingKeys,
} from "./types.js";

export interface NativeVerificationResult {
  valid: boolean;
  output: string;
}

interface RunResult {
  stdout: string;
  stderr: string;
}

const execFileAsync = promisify(execFile);

export interface NativeBackendConfig {
  binaryPath?: string;
  workDir?: string;
  inputDir?: string;
  vcSize?: "1k" | "2k" | "4k" | "8k";
  env?: Record<string, string>;
}

export class NativeBackend {
  private binaryPath: string;
  private workDir: string;
  private inputDir: string;
  private vcSize: "1k" | "2k" | "4k" | "8k";
  private env: Record<string, string>;

  constructor(config: NativeBackendConfig = {}) {
    this.binaryPath = config.binaryPath ?? this.findBinary();
    this.workDir = config.workDir ?? this.findWorkDir();
    this.inputDir = config.inputDir ?? join(this.workDir, "..", "circom", "inputs");
    this.vcSize = config.vcSize ?? "1k";
    this.env = {
      RUST_LOG: "info",
      ...this.buildDylibEnv(),
      ...config.env,
    };
  }

  private findBinary(): string {
    const candidates = [
      join(dirname(new URL(import.meta.url).pathname), "..", "..", "ecdsa-spartan2", "target", "release", "ecdsa-spartan2"),
      join(process.cwd(), "target", "release", "ecdsa-spartan2"),
    ];

    for (const path of candidates) {
      if (existsSync(path)) return path;
    }

    throw new SetupError(
      "KEYS_NOT_FOUND",
      "Could not find ecdsa-spartan2 binary. Build with: cargo build --release"
    );
  }

  private findWorkDir(): string {
    const candidates = [
      join(dirname(new URL(import.meta.url).pathname), "..", "..", "ecdsa-spartan2"),
      process.cwd(),
    ];

    for (const path of candidates) {
      if (existsSync(join(path, "Cargo.toml"))) return path;
    }

    return process.cwd();
  }

  // The binary links @rpath/libwitnesscalc_*.dylib but cargo doesn't embed an rpath.
  // When running via `cargo run`, Cargo sets DYLD_LIBRARY_PATH automatically;
  // when invoking via execFile we must set it ourselves.
  private buildDylibEnv(): Record<string, string> {
    const buildDir = join(this.workDir, "target", "release", "build");
    if (!existsSync(buildDir)) return {};

    const entries = readdirSync(buildDir);
    for (const entry of entries) {
      if (!entry.startsWith("ecdsa-spartan2-")) continue;
      const dylibDir = join(buildDir, entry, "out", "witnesscalc", "build_witnesscalc", "src");
      if (existsSync(join(dylibDir, "libwitnesscalc_jwt.dylib"))) {
        const existing = process.env.DYLD_LIBRARY_PATH ?? "";
        return { DYLD_LIBRARY_PATH: existing ? `${dylibDir}:${existing}` : dylibDir };
      }
    }

    return {};
  }

  private async run(args: string[], timeoutMs = 600_000): Promise<RunResult> {
    try {
      const { stdout, stderr } = await execFileAsync(this.binaryPath, args, {
        cwd: this.workDir,
        env: { ...process.env, ...this.env },
        timeout: timeoutMs,
        maxBuffer: 10 * 1024 * 1024,
      });
      return { stdout, stderr };
    } catch (error: unknown) {
      const execError = error as { code?: number; stderr?: string; stdout?: string; message?: string };
      throw new ProofError(
        "PROOF_GENERATION_FAILED",
        `Command failed (exit ${execError.code ?? "unknown"}): ${execError.stderr || execError.message || "Unknown error"}`,
        error
      );
    }
  }

  private withSize(args: string[]): string[] {
    return [...args, "--size", this.vcSize];
  }

  private withInput(args: string[], inputPath?: string): string[] {
    const sizedArgs = this.withSize(args);
    if (inputPath) sizedArgs.push("--input", inputPath);
    return sizedArgs;
  }

  async setupPrepare(inputPath?: string): Promise<void> {
    await this.run(this.withInput(["prepare", "setup"], inputPath), 1_200_000);
  }

  async setupShow(inputPath?: string): Promise<void> {
    await this.run(this.withInput(["show", "setup"], inputPath), 600_000);
  }

  async setupPrepare2Vc(inputPath?: string): Promise<void> {
    await this.setupPrepareMulti(2, inputPath);
  }

  async setupShow2Vc(inputPath?: string): Promise<void> {
    await this.setupShowMulti(2, inputPath);
  }

  async setupPrepareMulti(
    credentialCount = 2,
    inputPath?: string,
  ): Promise<void> {
    const profile = getMultiCredentialCircuitProfile(credentialCount);
    await this.run(
      this.withInput([profile.prepareCliName, "setup"], inputPath),
      1_800_000,
    );
  }

  async setupShowMulti(
    credentialCount = 2,
    inputPath?: string,
  ): Promise<void> {
    const profile = getPreparedMultiShowCircuitProfile(credentialCount);
    await this.run(
      this.withInput([profile.showCliName, "setup"], inputPath),
      600_000,
    );
  }

  async setupLinkMulti(
    credentialCount = 2,
    inputPath?: string,
  ): Promise<void> {
    const profile = getPreparedMultiShowCircuitProfile(credentialCount);
    await this.run(
      this.withInput([profile.linkCliName, "setup"], inputPath),
      600_000,
    );
  }

  async setup(inputPath?: string): Promise<void> {
    await this.setupPrepare(inputPath);
    await this.setupShow(inputPath);
  }

  async provePrepare(inputPath?: string): Promise<void> {
    await this.run(this.withInput(["prepare", "prove"], inputPath), 300_000);
  }

  async proveShow(inputPath?: string): Promise<void> {
    await this.run(this.withInput(["show", "prove"], inputPath), 120_000);
  }

  async provePrepare2Vc(inputPath?: string): Promise<void> {
    await this.provePrepareMulti(2, inputPath);
  }

  async proveShow2Vc(inputPath?: string): Promise<void> {
    await this.proveShowMulti(2, inputPath);
  }

  async provePrepareMulti(
    credentialCount = 2,
    inputPath?: string,
  ): Promise<void> {
    const profile = getMultiCredentialCircuitProfile(credentialCount);
    await this.run(
      this.withInput([profile.prepareCliName, "prove"], inputPath),
      600_000,
    );
  }

  async proveShowMulti(
    credentialCount = 2,
    inputPath?: string,
  ): Promise<void> {
    const profile = getPreparedMultiShowCircuitProfile(credentialCount);
    await this.run(
      this.withInput([profile.showCliName, "prove"], inputPath),
      120_000,
    );
  }

  async proveLinkMulti(
    credentialCount = 2,
    inputPath?: string,
  ): Promise<void> {
    const profile = getPreparedMultiShowCircuitProfile(credentialCount);
    await this.run(
      this.withInput([profile.linkCliName, "prove"], inputPath),
      120_000,
    );
  }

  async generateSharedBlinds(): Promise<void> {
    await this.run(this.withSize(["generate_shared_blinds"]));
  }

  async reblindPrepare(): Promise<void> {
    await this.run(this.withSize(["prepare", "reblind"]), 300_000);
  }

  async reblindShow(): Promise<void> {
    await this.run(this.withSize(["show", "reblind"]), 120_000);
  }

  async reblindPrepare2Vc(): Promise<void> {
    await this.reblindPrepareMulti(2);
  }

  async reblindShow2Vc(): Promise<void> {
    await this.reblindShowMulti(2);
  }

  async reblindPrepareMulti(credentialCount = 2): Promise<void> {
    const profile = getMultiCredentialCircuitProfile(credentialCount);
    await this.run(
      this.withSize([profile.prepareCliName, "reblind"]),
      600_000,
    );
  }

  async reblindShowMulti(credentialCount = 2): Promise<void> {
    const profile = getPreparedMultiShowCircuitProfile(credentialCount);
    await this.run(this.withSize([profile.showCliName, "reblind"]), 120_000);
  }

  async reblindLinkMulti(credentialCount = 2): Promise<void> {
    const profile = getPreparedMultiShowCircuitProfile(credentialCount);
    await this.run(this.withSize([profile.linkCliName, "reblind"]), 120_000);
  }

  async verifyPrepare(): Promise<NativeVerificationResult> {
    const { stdout, stderr } = await this.run(this.withSize(["prepare", "verify"]));
    const output = stdout + stderr;
    return {
      valid: output.includes("Verification successful"),
      output,
    };
  }

  async verifyShow(): Promise<NativeVerificationResult> {
    const { stdout, stderr } = await this.run(this.withSize(["show", "verify"]));
    const output = stdout + stderr;
    return {
      valid: output.includes("Verification successful"),
      output,
    };
  }

  async verifyPrepare2Vc(): Promise<NativeVerificationResult> {
    return this.verifyPrepareMulti(2);
  }

  async verifyShow2Vc(): Promise<NativeVerificationResult> {
    return this.verifyShowMulti(2);
  }

  async verifyPrepareMulti(
    credentialCount = 2,
  ): Promise<NativeVerificationResult> {
    const profile = getMultiCredentialCircuitProfile(credentialCount);
    const { stdout, stderr } = await this.run(
      this.withSize([profile.prepareCliName, "verify"]),
    );
    const output = stdout + stderr;
    return {
      valid: output.includes("Verification successful"),
      output,
    };
  }

  async verifyShowMulti(
    credentialCount = 2,
  ): Promise<NativeVerificationResult> {
    const profile = getPreparedMultiShowCircuitProfile(credentialCount);
    const { stdout, stderr } = await this.run(
      this.withSize([profile.showCliName, "verify"]),
    );
    const output = stdout + stderr;
    return {
      valid: output.includes("Verification successful"),
      output,
    };
  }

  async verifyLinkMulti(
    credentialCount = 2,
  ): Promise<NativeVerificationResult> {
    const profile = getPreparedMultiShowCircuitProfile(credentialCount);
    const { stdout, stderr } = await this.run(
      this.withSize([profile.linkCliName, "verify"]),
    );
    const output = stdout + stderr;
    return {
      valid: output.includes("Verification successful"),
      output,
    };
  }

  async runBenchmark(inputPath?: string): Promise<string> {
    const { stdout, stderr } = await this.run(
      this.withInput(["benchmark"], inputPath),
      1_800_000,
    );
    return stdout + stderr;
  }

  async proveAll(jwtInputPath?: string, showInputPath?: string): Promise<void> {
    await this.generateSharedBlinds();
    await this.provePrepare(jwtInputPath);
    await this.reblindPrepare();
    await this.proveShow(showInputPath);
    await this.reblindShow();
  }

  async proveAll2Vc(prepareInputPath?: string, showInputPath?: string): Promise<void> {
    await this.proveAllMulti(2, prepareInputPath, showInputPath);
  }

  async proveAllMulti(
    credentialCount = 2,
    prepareInputPath?: string,
    showInputPath?: string,
  ): Promise<void> {
    await this.generateSharedBlinds();
    await this.provePrepareMulti(credentialCount, prepareInputPath);
    await this.reblindPrepareMulti(credentialCount);
    await this.proveShowMulti(credentialCount, showInputPath);
    await this.reblindShowMulti(credentialCount);
  }

  async loadArtifact(filename: string): Promise<Uint8Array> {
    const path = this.resolveArtifactPath(filename);
    return new Uint8Array(await readFile(path));
  }

  async saveArtifact(filename: string, data: Uint8Array): Promise<void> {
    const dir = join(this.workDir, "keys");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, filename), data);
  }

  private resolveArtifactPath(filename: string): string {
    const direct = join(this.workDir, "keys", filename);
    if (existsSync(direct)) return direct;

    return join(this.workDir, "keys", `${this.vcSize}_${filename}`);
  }

  private artifactExists(filename: string): boolean {
    return (
      existsSync(join(this.workDir, "keys", filename)) ||
      existsSync(join(this.workDir, "keys", `${this.vcSize}_${filename}`))
    );
  }

  async loadKeys(): Promise<KeySet> {
    const [ppk, pvk, spk, svk] = await Promise.all([
      this.loadArtifact("prepare_proving.key"),
      this.loadArtifact("prepare_verifying.key"),
      this.loadArtifact("show_proving.key"),
      this.loadArtifact("show_verifying.key"),
    ]);
    const jwtParams = jwtParamsForVcSize(this.vcSize);

    return {
      prepareProvingKey: ppk,
      prepareVerifyingKey: pvk,
      showProvingKey: spk,
      showVerifyingKey: svk,
      jwtParams,
      verifyingKeys(): VerifyingKeys {
        return { prepareVerifyingKey: pvk, showVerifyingKey: svk };
      },
      serialize(): SerializedKeySet {
        return {
          prepareProvingKey: ppk,
          prepareVerifyingKey: pvk,
          showProvingKey: spk,
          showVerifyingKey: svk,
          jwtParams,
        };
      },
    };
  }

  async loadMultiKeys(credentialCount = 2): Promise<KeySet> {
    const profile = getMultiCredentialCircuitProfile(credentialCount);
    const [ppk, pvk, spk, svk] = await Promise.all([
      this.loadArtifact(`${profile.prepareCircuitStem}_proving.key`),
      this.loadArtifact(`${profile.prepareCircuitStem}_verifying.key`),
      this.loadArtifact(`${profile.showCircuitStem}_proving.key`),
      this.loadArtifact(`${profile.showCircuitStem}_verifying.key`),
    ]);
    const jwtParams = jwtParamsForVcSize(this.vcSize);

    return {
      prepareProvingKey: ppk,
      prepareVerifyingKey: pvk,
      showProvingKey: spk,
      showVerifyingKey: svk,
      jwtParams,
      verifyingKeys(): VerifyingKeys {
        return { prepareVerifyingKey: pvk, showVerifyingKey: svk };
      },
      serialize(): SerializedKeySet {
        return {
          prepareProvingKey: ppk,
          prepareVerifyingKey: pvk,
          showProvingKey: spk,
          showVerifyingKey: svk,
          jwtParams,
        };
      },
    };
  }

  async loadPreparedMultiKeys(
    credentialCount = 2,
  ): Promise<PreparedMultiKeySet> {
    const profile = getPreparedMultiShowCircuitProfile(credentialCount);
    const [ppk, pvk, spk, svk, lpk, lvk] = await Promise.all([
      this.loadArtifact("prepare_proving.key"),
      this.loadArtifact("prepare_verifying.key"),
      this.loadArtifact(`${profile.showCircuitStem}_proving.key`),
      this.loadArtifact(`${profile.showCircuitStem}_verifying.key`),
      this.loadArtifact(`${profile.linkCircuitStem}_proving.key`),
      this.loadArtifact(`${profile.linkCircuitStem}_verifying.key`),
    ]);
    const jwtParams = jwtParamsForVcSize(this.vcSize);

    return {
      prepareProvingKey: ppk,
      prepareVerifyingKey: pvk,
      showProvingKey: spk,
      showVerifyingKey: svk,
      linkProvingKey: lpk,
      linkVerifyingKey: lvk,
      jwtParams,
      verifyingKeys(): VerifyingKeys {
        return { prepareVerifyingKey: pvk, showVerifyingKey: svk };
      },
      preparedMultiVerifyingKeys(): PreparedMultiVerifyingKeys {
        return {
          prepareVerifyingKey: pvk,
          showVerifyingKey: svk,
          linkVerifyingKey: lvk,
        };
      },
      serialize(): SerializedPreparedMultiKeySet {
        return {
          prepareProvingKey: ppk,
          prepareVerifyingKey: pvk,
          showProvingKey: spk,
          showVerifyingKey: svk,
          linkProvingKey: lpk,
          linkVerifyingKey: lvk,
          jwtParams,
        };
      },
    };
  }

  async loadProofs(): Promise<{
    prepareProof: Uint8Array;
    showProof: Uint8Array;
    prepareInstance: Uint8Array;
    showInstance: Uint8Array;
    prepareWitness: Uint8Array;
    showWitness: Uint8Array;
    sharedBlinds: Uint8Array;
  }> {
    const [pp, sp, pi, si, pw, sw, sb] = await Promise.all([
      this.loadArtifact("prepare_proof.bin"),
      this.loadArtifact("show_proof.bin"),
      this.loadArtifact("prepare_instance.bin"),
      this.loadArtifact("show_instance.bin"),
      this.loadArtifact("prepare_witness.bin"),
      this.loadArtifact("show_witness.bin"),
      this.loadArtifact("shared_blinds.bin"),
    ]);

    return {
      prepareProof: pp,
      showProof: sp,
      prepareInstance: pi,
      showInstance: si,
      prepareWitness: pw,
      showWitness: sw,
      sharedBlinds: sb,
    };
  }

  async loadMultiProofs(credentialCount = 2): Promise<{
    prepareProof: Uint8Array;
    showProof: Uint8Array;
    prepareInstance: Uint8Array;
    showInstance: Uint8Array;
    prepareWitness: Uint8Array;
    showWitness: Uint8Array;
    sharedBlinds: Uint8Array;
  }> {
    const profile = getMultiCredentialCircuitProfile(credentialCount);
    const [pp, sp, pi, si, pw, sw, sb] = await Promise.all([
      this.loadArtifact(`${profile.prepareCircuitStem}_proof.bin`),
      this.loadArtifact(`${profile.showCircuitStem}_proof.bin`),
      this.loadArtifact(`${profile.prepareCircuitStem}_instance.bin`),
      this.loadArtifact(`${profile.showCircuitStem}_instance.bin`),
      this.loadArtifact(`${profile.prepareCircuitStem}_witness.bin`),
      this.loadArtifact(`${profile.showCircuitStem}_witness.bin`),
      this.loadArtifact("shared_blinds.bin"),
    ]);

    return {
      prepareProof: pp,
      showProof: sp,
      prepareInstance: pi,
      showInstance: si,
      prepareWitness: pw,
      showWitness: sw,
      sharedBlinds: sb,
    };
  }

  get directory(): string {
    return this.workDir;
  }

  get keysDir(): string {
    return join(this.workDir, "keys");
  }

  get keysExist(): boolean {
    return (
      this.artifactExists("prepare_proving.key") &&
      this.artifactExists("show_proving.key")
    );
  }

  get multiKeysExist(): boolean {
    return this.hasMultiKeys();
  }

  hasMultiKeys(credentialCount = 2): boolean {
    const profile = getMultiCredentialCircuitProfile(credentialCount);
    return (
      this.artifactExists(`${profile.prepareCircuitStem}_proving.key`) &&
      this.artifactExists(`${profile.showCircuitStem}_proving.key`)
    );
  }

  hasPreparedMultiKeys(credentialCount = 2): boolean {
    const profile = getPreparedMultiShowCircuitProfile(credentialCount);
    return (
      this.artifactExists("prepare_proving.key") &&
      this.artifactExists(`${profile.showCircuitStem}_proving.key`) &&
      this.artifactExists(`${profile.linkCircuitStem}_proving.key`)
    );
  }

  get proofsExist(): boolean {
    return (
      this.artifactExists("prepare_proof.bin") &&
      this.artifactExists("show_proof.bin")
    );
  }

  get multiProofsExist(): boolean {
    return this.hasMultiProofs();
  }

  hasMultiProofs(credentialCount = 2): boolean {
    const profile = getMultiCredentialCircuitProfile(credentialCount);
    return (
      this.artifactExists(`${profile.prepareCircuitStem}_proof.bin`) &&
      this.artifactExists(`${profile.showCircuitStem}_proof.bin`)
    );
  }
}

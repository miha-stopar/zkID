import { describe, it, expect } from "vitest";
import { runEngine, getSelectedModuleIds } from "@/lib/rules/engine";
import type { Scenario } from "@/lib/scenario/schema";
import { DEFAULT_SCENARIO } from "@/lib/scenario/defaults";

function makeScenario(overrides: Partial<Scenario> = {}): Scenario {
  return { ...DEFAULT_SCENARIO, ...overrides };
}

describe("Rule Engine", () => {
  it("always includes core modules", () => {
    const output = runEngine(makeScenario());
    const ids = getSelectedModuleIds(output);
    expect(ids).toContain("issuer_sig_verify");
    expect(ids).toContain("attribute_commitments");
    expect(ids).toContain("selective_disclosure");
    expect(ids).toContain("prepare_show_split");
  });

  it("adds verifier_challenge_nonce when antiReplay is nonce_only", () => {
    const output = runEngine(makeScenario({ antiReplay: "nonce_only" }));
    const ids = getSelectedModuleIds(output);
    expect(ids).toContain("verifier_challenge_nonce");
  });

  it("does not add verifier_challenge_nonce when antiReplay is none", () => {
    const output = runEngine(makeScenario({ antiReplay: "none" }));
    const ids = getSelectedModuleIds(output);
    expect(ids).not.toContain("verifier_challenge_nonce");
  });

  it("adds reblind_rerandomize for repeat presentations", () => {
    const output = runEngine(makeScenario({ presentationFrequency: "repeat" }));
    const ids = getSelectedModuleIds(output);
    expect(ids).toContain("reblind_rerandomize");
    expect(output.explanations.some((e) => e.includes("repeat presentations"))).toBe(true);
  });

  it("adds reblind_rerandomize when unlinkabilityGoal is not none", () => {
    const output = runEngine(makeScenario({ unlinkabilityGoal: "cross_verifiers" }));
    const ids = getSelectedModuleIds(output);
    expect(ids).toContain("reblind_rerandomize");
    expect(output.explanations.some((e) => e.includes("unlinkability goal"))).toBe(true);
  });

  it("does not add reblind for one_time + unlinkability none", () => {
    const output = runEngine(
      makeScenario({ presentationFrequency: "one_time", unlinkabilityGoal: "none" })
    );
    const ids = getSelectedModuleIds(output);
    expect(ids).not.toContain("reblind_rerandomize");
  });

  it("adds nullifier_antireplay when antiReplay is nullifier", () => {
    const output = runEngine(makeScenario({ antiReplay: "nullifier" }));
    const ids = getSelectedModuleIds(output);
    expect(ids).toContain("nullifier_antireplay");
    expect(ids).toContain("verifier_challenge_nonce"); // also nonce
  });

  it("adds device_binding when required", () => {
    const output = runEngine(makeScenario({ deviceBinding: "required" }));
    const ids = getSelectedModuleIds(output);
    expect(ids).toContain("device_binding");
  });

  it("does not add device_binding when recommended (only on required)", () => {
    const output = runEngine(makeScenario({ deviceBinding: "recommended" }));
    const ids = getSelectedModuleIds(output);
    expect(ids).not.toContain("device_binding");
  });

  it("adds offchain_verify for offchain target", () => {
    const output = runEngine(makeScenario({ verificationTarget: "offchain" }));
    const ids = getSelectedModuleIds(output);
    expect(ids).toContain("offchain_verify");
    expect(ids).not.toContain("onchain_verify");
  });

  it("adds onchain_verify for onchain target", () => {
    const output = runEngine(makeScenario({ verificationTarget: "onchain" }));
    const ids = getSelectedModuleIds(output);
    expect(ids).toContain("onchain_verify");
    expect(ids).not.toContain("offchain_verify");
  });

  it("adds dual_verify_planB + both verify modules for both target", () => {
    const output = runEngine(makeScenario({ verificationTarget: "both" }));
    const ids = getSelectedModuleIds(output);
    expect(ids).toContain("dual_verify_planB");
    expect(ids).toContain("offchain_verify");
    expect(ids).toContain("onchain_verify");
  });

  it("warns about in_proof_future revocation", () => {
    const output = runEngine(makeScenario({ revocationHandling: "in_proof_future" }));
    expect(output.warnings.some((w) => w.includes("not yet implemented"))).toBe(true);
  });

  it("resolves dependencies automatically (selective_disclosure requires commitments)", () => {
    // selective_disclosure requires commitments — both are always-on so this is satisfied
    const output = runEngine(makeScenario());
    const ids = getSelectedModuleIds(output);
    expect(ids).toContain("attribute_commitments");
    expect(ids).toContain("selective_disclosure");
  });

  // Full scenario integration tests
  it("one-time PTT badge scenario produces expected modules", () => {
    const output = runEngine({
      presentationFrequency: "one_time",
      verifierTopology: "single_verifier",
      unlinkabilityGoal: "none",
      antiReplay: "nonce_only",
      deviceBinding: "required",
      verificationTarget: "offchain",
      credentialFormat: "sd_jwt",
      revocationHandling: "none",
    });
    const ids = getSelectedModuleIds(output);
    expect(ids).toContain("device_binding");
    expect(ids).toContain("offchain_verify");
    expect(ids).toContain("verifier_challenge_nonce");
    expect(ids).not.toContain("reblind_rerandomize");
    expect(ids).not.toContain("nullifier_antireplay");
  });

  it("repeat alcohol purchase scenario produces expected modules", () => {
    const output = runEngine({
      presentationFrequency: "repeat",
      verifierTopology: "multi_verifier_possible_collusion",
      unlinkabilityGoal: "cross_verifiers",
      antiReplay: "nullifier",
      deviceBinding: "recommended",
      verificationTarget: "offchain",
      credentialFormat: "sd_jwt",
      revocationHandling: "out_of_band",
    });
    const ids = getSelectedModuleIds(output);
    expect(ids).toContain("reblind_rerandomize");
    expect(ids).toContain("nullifier_antireplay");
    expect(ids).toContain("verifier_challenge_nonce");
    expect(ids).toContain("device_binding"); // repeat presentations require device binding
    expect(ids).toContain("offchain_verify");
    expect(output.warnings).toHaveLength(0);
  });

  it("output modules are deterministically ordered by registry", () => {
    const out1 = runEngine(makeScenario({ verificationTarget: "both", antiReplay: "nullifier" }));
    const out2 = runEngine(makeScenario({ verificationTarget: "both", antiReplay: "nullifier" }));
    expect(getSelectedModuleIds(out1)).toEqual(getSelectedModuleIds(out2));
  });
});

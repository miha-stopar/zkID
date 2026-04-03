import { describe, it, expect } from "vitest";
import { generateThreatModel } from "../generator";
import { renderThreatModelMarkdown } from "../markdown";
import type { Scenario } from "../../scenario/schema";

const BASE_SCENARIO: Scenario = {
  presentationFrequency: "one_time",
  verifierTopology: "single_verifier",
  unlinkabilityGoal: "none",
  antiReplay: "nonce_only",
  deviceBinding: "none",
  verificationTarget: "offchain",
  credentialFormat: "sd_jwt",
  revocationHandling: "none",
};

const FULL_MODULES = [
  "prepare_show_split",
  "issuer_sig_verify",
  "attribute_commitments",
  "selective_disclosure",
  "reblind_rerandomize",
  "verifier_challenge_nonce",
  "nullifier_antireplay",
  "device_binding",
  "offchain_verify",
];

describe("Threat Model Generator", () => {
  it("marks linkability threats applicable and high severity when cross-verifier unlinkability required but reblind missing", () => {
    const scenario: Scenario = {
      ...BASE_SCENARIO,
      unlinkabilityGoal: "cross_verifiers",
      verifierTopology: "multi_verifier_possible_collusion",
    };
    const modules = FULL_MODULES.filter((m) => m !== "reblind_rerandomize");

    const model = generateThreatModel({ scenario, selectedModules: modules });

    // T-UL-01: cross-session linkability
    const ul01 = model.checklist
      .flatMap((c) => c.items)
      .find((t) => t.threatId === "T-UL-01");
    expect(ul01).toBeDefined();
    expect(ul01!.applicable).toBe(true);
    expect(ul01!.severity).toBe("high");

    // T-UL-02: cross-verifier linkability
    const ul02 = model.checklist
      .flatMap((c) => c.items)
      .find((t) => t.threatId === "T-UL-02");
    expect(ul02).toBeDefined();
    expect(ul02!.applicable).toBe(true);
    expect(ul02!.severity).toBe("high");

    // T-VC-01: verifier collusion
    const vc01 = model.checklist
      .flatMap((c) => c.items)
      .find((t) => t.threatId === "T-VC-01");
    expect(vc01).toBeDefined();
    expect(vc01!.applicable).toBe(true);
    expect(vc01!.severity).toBe("high");

    // Mitigation should be unsatisfied (reblind is missing)
    expect(ul01!.mitigations[0].satisfied).toBe(false);
  });

  it("marks device sharing threat applicable and high when deviceBinding=required but module missing", () => {
    const scenario: Scenario = {
      ...BASE_SCENARIO,
      deviceBinding: "required",
    };
    const modules = FULL_MODULES.filter((m) => m !== "device_binding");

    const model = generateThreatModel({ scenario, selectedModules: modules });

    const ds01 = model.checklist
      .flatMap((c) => c.items)
      .find((t) => t.threatId === "T-DS-01");
    expect(ds01).toBeDefined();
    expect(ds01!.applicable).toBe(true);
    expect(ds01!.severity).toBe("high");
    expect(ds01!.mitigations[0].satisfied).toBe(false);
  });

  it("marks replay/double-use threat high with unsatisfied mitigation when nullifier required but missing", () => {
    const scenario: Scenario = {
      ...BASE_SCENARIO,
      antiReplay: "nullifier",
    };
    const modules = FULL_MODULES.filter((m) => m !== "nullifier_antireplay");

    const model = generateThreatModel({ scenario, selectedModules: modules });

    const rp02 = model.checklist
      .flatMap((c) => c.items)
      .find((t) => t.threatId === "T-RP-02");
    expect(rp02).toBeDefined();
    expect(rp02!.applicable).toBe(true);
    expect(rp02!.severity).toBe("high");
    expect(rp02!.mitigations[0].satisfied).toBe(false);
    expect(rp02!.mitigations[0].how).toContain("nullifier_antireplay");
  });

  it("marks mitigations satisfied when required modules are present", () => {
    const scenario: Scenario = {
      ...BASE_SCENARIO,
      unlinkabilityGoal: "cross_verifiers",
      verifierTopology: "multi_verifier_possible_collusion",
      antiReplay: "nullifier",
      deviceBinding: "required",
    };

    const model = generateThreatModel({ scenario, selectedModules: FULL_MODULES });

    // Linkability mitigations should be satisfied (reblind present)
    const ul01 = model.checklist
      .flatMap((c) => c.items)
      .find((t) => t.threatId === "T-UL-01");
    // With reblind present, T-UL-01 should not be applicable
    // (appliesWhen checks !mods.includes("reblind_rerandomize"))
    expect(ul01!.applicable).toBe(false);

    // Device binding present, so T-DS-01 should not be applicable
    const ds01 = model.checklist
      .flatMap((c) => c.items)
      .find((t) => t.threatId === "T-DS-01");
    expect(ds01!.applicable).toBe(false);
  });

  it("includes top risks sorted by severity then by unsatisfied mitigations", () => {
    const scenario: Scenario = {
      ...BASE_SCENARIO,
      unlinkabilityGoal: "cross_verifiers",
      verifierTopology: "multi_verifier_possible_collusion",
      deviceBinding: "required",
    };
    const modules = ["prepare_show_split", "issuer_sig_verify", "attribute_commitments", "selective_disclosure", "verifier_challenge_nonce", "offchain_verify"];

    const model = generateThreatModel({ scenario, selectedModules: modules });

    expect(model.summary.topRisks.length).toBeGreaterThan(0);
    // First risk should be high severity
    expect(model.summary.topRisks[0].severity).toBe("high");
  });

  it("includes warnings for high-severity unmitigated threats", () => {
    const scenario: Scenario = {
      ...BASE_SCENARIO,
      unlinkabilityGoal: "cross_verifiers",
      deviceBinding: "required",
    };
    const modules = ["prepare_show_split", "issuer_sig_verify", "offchain_verify"];

    const model = generateThreatModel({ scenario, selectedModules: modules });

    expect(model.warnings.some((w) => w.includes("high-severity"))).toBe(true);
  });

  it("returns assumptions based on selected modules", () => {
    const model = generateThreatModel({
      scenario: BASE_SCENARIO,
      selectedModules: FULL_MODULES,
    });

    expect(model.summary.assumptions).toContain(
      "The issuer's public key is authentic and distributed via a trusted channel."
    );
    expect(model.summary.assumptions).toContain(
      "The device hardware key store is secure and not compromised."
    );
    expect(model.summary.assumptions).toContain(
      "The verifier maintains a complete and consistent spent-nullifier set."
    );
  });

  it("includes on-chain operational risk when verification target is onchain", () => {
    const scenario: Scenario = {
      ...BASE_SCENARIO,
      verificationTarget: "onchain",
    };

    const model = generateThreatModel({
      scenario,
      selectedModules: [...FULL_MODULES, "onchain_verify"],
    });

    const ok01 = model.checklist
      .flatMap((c) => c.items)
      .find((t) => t.threatId === "T-OK-01");
    expect(ok01).toBeDefined();
    expect(ok01!.applicable).toBe(true);
    expect(ok01!.severity).toBe("medium");
  });
});

describe("Markdown Renderer", () => {
  it("produces stable deterministic output", () => {
    const scenario: Scenario = {
      ...BASE_SCENARIO,
      unlinkabilityGoal: "cross_verifiers",
      verifierTopology: "multi_verifier_possible_collusion",
    };
    const modules = [
      "prepare_show_split",
      "issuer_sig_verify",
      "attribute_commitments",
      "selective_disclosure",
      "reblind_rerandomize",
      "verifier_challenge_nonce",
      "offchain_verify",
    ];

    const model = generateThreatModel({ scenario, selectedModules: modules });
    const md1 = renderThreatModelMarkdown(model, scenario, modules);
    const md2 = renderThreatModelMarkdown(model, scenario, modules);

    expect(md1).toBe(md2);
  });

  it("contains expected sections", () => {
    const model = generateThreatModel({
      scenario: BASE_SCENARIO,
      selectedModules: FULL_MODULES,
    });
    const md = renderThreatModelMarkdown(model, BASE_SCENARIO, FULL_MODULES);

    expect(md).toContain("# Threat Model Report");
    expect(md).toContain("## Scenario");
    expect(md).toContain("## Selected Modules");
    expect(md).toContain("## Top Risks");
    expect(md).toContain("## Assumptions");
    expect(md).toContain("## Out of Scope");
    expect(md).toContain("## Threat Checklist");
    expect(md).toContain("checklist-based assessment");
  });

  it("includes scenario parameter values in table", () => {
    const md = renderThreatModelMarkdown(
      generateThreatModel({ scenario: BASE_SCENARIO, selectedModules: [] }),
      BASE_SCENARIO,
      []
    );

    expect(md).toContain("one_time");
    expect(md).toContain("single_verifier");
    expect(md).toContain("nonce_only");
    expect(md).toContain("offchain");
  });

  it("lists selected modules", () => {
    const modules = ["issuer_sig_verify", "selective_disclosure"];
    const md = renderThreatModelMarkdown(
      generateThreatModel({ scenario: BASE_SCENARIO, selectedModules: modules }),
      BASE_SCENARIO,
      modules
    );

    expect(md).toContain("- issuer_sig_verify");
    expect(md).toContain("- selective_disclosure");
  });

  it("marks applicable threats with [x] and non-applicable with [ ]", () => {
    const md = renderThreatModelMarkdown(
      generateThreatModel({ scenario: BASE_SCENARIO, selectedModules: [] }),
      BASE_SCENARIO,
      []
    );

    // With no modules, many threats should be applicable
    expect(md).toContain("- [x]");
    // Some threats may not be applicable
    expect(md).toContain("- [ ]");
  });
});

import type { Scenario } from "../scenario/schema";
import type {
  ThreatModel,
  ThreatCategoryChecklist,
  ThreatChecklistItem,
} from "./types";
import { THREAT_CATEGORIES } from "./types";
import { THREAT_TEMPLATES } from "./templates";

const SEVERITY_SCORE: Record<string, number> = {
  high: 3,
  medium: 2,
  low: 1,
};

export function generateThreatModel(input: {
  scenario: Scenario;
  selectedModules: string[];
}): ThreatModel {
  const { scenario, selectedModules } = input;
  const moduleSet = new Set(selectedModules);

  // Build checklist items from all templates
  const allItems: (ThreatChecklistItem & { category: string })[] = [];

  for (const template of THREAT_TEMPLATES) {
    const applicable = template.appliesWhen(scenario, selectedModules);

    const mitigations = template.mitigations.map((m) => {
      const satisfied =
        m.dependsOnModules.length === 0 ||
        m.dependsOnModules.every((dep) => moduleSet.has(dep));
      return {
        id: m.id,
        title: m.title,
        satisfied,
        how: satisfied
          ? m.dependsOnModules.length > 0
            ? `Satisfied by modules: ${m.dependsOnModules.join(", ")}`
            : "Operational measure (no module dependency)"
          : m.dependsOnModules.length > 0
            ? `Missing modules: ${m.dependsOnModules.filter((d) => !moduleSet.has(d)).join(", ")}`
            : "Requires operational action",
      };
    });

    const whyApplicable = applicable
      ? buildWhyApplicable(template.id, scenario, selectedModules)
      : "Not applicable to current scenario configuration.";

    allItems.push({
      category: template.category,
      threatId: template.id,
      title: template.title,
      severity: template.severity,
      applicable,
      selected: applicable,
      whyApplicable,
      mitigations,
      riskIfUnmitigated: template.description,
      detectionSignals: template.detectionSignals,
    });
  }

  // Group by category
  const checklist: ThreatCategoryChecklist[] = THREAT_CATEGORIES.map(
    (category) => ({
      category,
      items: allItems
        .filter((item) => item.category === category)
        .map(({ category: _, ...rest }) => rest),
    })
  ).filter((group) => group.items.length > 0);

  // Compute top risks: applicable threats, sorted by severity desc then by ID for determinism
  const applicableThreats = allItems.filter((t) => t.applicable);
  const sortedByRisk = [...applicableThreats].sort((a, b) => {
    const scoreDiff =
      (SEVERITY_SCORE[b.severity] ?? 0) - (SEVERITY_SCORE[a.severity] ?? 0);
    if (scoreDiff !== 0) return scoreDiff;
    // Secondary: threats with unsatisfied mitigations rank higher
    const aUnsatisfied = a.mitigations.filter((m) => !m.satisfied).length;
    const bUnsatisfied = b.mitigations.filter((m) => !m.satisfied).length;
    if (bUnsatisfied !== aUnsatisfied) return bUnsatisfied - aUnsatisfied;
    // Tertiary: deterministic by ID
    return a.threatId.localeCompare(b.threatId);
  });

  const topRisks = sortedByRisk.slice(0, 5).map((t) => ({
    id: t.threatId,
    title: t.title,
    severity: t.severity,
    why: t.whyApplicable,
  }));

  // Build assumptions
  const assumptions: string[] = [];
  if (moduleSet.has("issuer_sig_verify")) {
    assumptions.push(
      "The issuer's public key is authentic and distributed via a trusted channel."
    );
  }
  if (moduleSet.has("device_binding")) {
    assumptions.push(
      "The device hardware key store is secure and not compromised."
    );
  }
  if (moduleSet.has("nullifier_antireplay")) {
    assumptions.push(
      "The verifier maintains a complete and consistent spent-nullifier set."
    );
  }
  if (
    scenario.verificationTarget === "onchain" ||
    scenario.verificationTarget === "both"
  ) {
    assumptions.push(
      "The on-chain verifier contract is correctly deployed and matches the proving circuit."
    );
  }
  assumptions.push(
    "Cryptographic primitives (hash functions, signature schemes, commitment schemes) are implemented correctly and use secure parameters."
  );

  // Out of scope
  const outOfScope: string[] = [
    "Network-level attacks (TLS interception, DNS spoofing) — assumed secure transport.",
    "Issuer misbehavior at issuance time (issuing incorrect attributes).",
    "Physical coercion or social engineering attacks on the holder.",
  ];
  if (scenario.revocationHandling === "none") {
    outOfScope.push(
      "Credential revocation — no revocation mechanism is configured."
    );
  }

  // Build warnings
  const warnings: string[] = [];
  const highUnmitigated = applicableThreats.filter(
    (t) =>
      t.severity === "high" && t.mitigations.some((m) => !m.satisfied)
  );
  if (highUnmitigated.length > 0) {
    warnings.push(
      `${highUnmitigated.length} high-severity threat(s) have unsatisfied mitigations.`
    );
  }
  if (scenario.revocationHandling === "in_proof_future") {
    warnings.push(
      "In-proof revocation is selected but not yet implemented — no active revocation enforcement."
    );
  }

  return { summary: { topRisks, assumptions, outOfScope }, checklist, warnings };
}

function buildWhyApplicable(
  threatId: string,
  scenario: Scenario,
  selectedModules: string[]
): string {
  const mods = new Set(selectedModules);
  switch (threatId) {
    case "T-SF-01":
      return "Issuer signature verification module is not selected.";
    case "T-SF-02":
      return "Selective disclosure is present without attribute commitments.";
    case "T-ZK-01":
      return "Selective disclosure module is not selected; all attributes will be revealed.";
    case "T-UL-01":
      return `Unlinkability goal is '${scenario.unlinkabilityGoal}' but reblind/rerandomize is missing.`;
    case "T-UL-02":
      return "Multi-verifier topology with possible collusion, but reblind is missing.";
    case "T-UL-03":
      return "Repeat presentations without rerandomization allow session-level tracking.";
    case "T-RP-01":
      return `Anti-replay is '${scenario.antiReplay}' but verifier challenge nonce is missing.`;
    case "T-RP-02":
      return "Nullifier anti-replay required but nullifier module is missing.";
    case "T-RP-03":
      return "Nonce module is present; ensure nonces are cryptographically random and never reused.";
    case "T-DS-01":
      return "Device binding is required but the device binding module is not selected.";
    case "T-DS-02":
      return "Device binding is recommended but not included — credentials may be shared.";
    case "T-IT-01":
      return `Unlinkability goal is '${scenario.unlinkabilityGoal}'; stable credential identifiers could enable issuer tracking.`;
    case "T-IT-02":
      return "Out-of-band revocation requires contacting the issuer, enabling usage tracking.";
    case "T-VC-01":
      return "Multi-verifier topology with possible collusion, but no rerandomization to prevent cross-verifier linkage.";
    case "T-VC-02":
      return "Rerandomization is active but colluding verifiers may still correlate via disclosed attribute combinations.";
    case "T-DR-01":
      return "No revocation handling is configured.";
    case "T-DR-02":
      return "In-proof revocation is selected but marked as future — not yet enforced.";
    case "T-SC-01":
      return "All implementations may be subject to side-channel attacks on proof generation.";
    case "T-SC-02":
      return "All implementations should audit logging behavior for credential data leakage.";
    case "T-OK-01":
      return `Verification target is '${scenario.verificationTarget}'; on-chain verification has gas, contract audit, and key management constraints.`;
    case "T-OK-02":
      return "Issuer key compromise is a universal risk without a rotation plan.";
    default:
      return "Applicable to current scenario.";
  }
}

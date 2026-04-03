import type { Scenario } from "../scenario/schema";
import type { ThreatModel } from "./types";
import { THREAT_CATEGORY_LABELS } from "./types";

export function renderThreatModelMarkdown(
  model: ThreatModel,
  scenario: Scenario,
  selectedModules: string[]
): string {
  const lines: string[] = [];

  lines.push("# Threat Model Report");
  lines.push("");
  lines.push("## Scenario");
  lines.push("");
  lines.push("| Parameter | Value |");
  lines.push("|---|---|");
  lines.push(`| Presentation Frequency | ${scenario.presentationFrequency} |`);
  lines.push(`| Verifier Topology | ${scenario.verifierTopology} |`);
  lines.push(`| Unlinkability Goal | ${scenario.unlinkabilityGoal} |`);
  lines.push(`| Anti-Replay | ${scenario.antiReplay} |`);
  lines.push(`| Device Binding | ${scenario.deviceBinding} |`);
  lines.push(`| Verification Target | ${scenario.verificationTarget} |`);
  lines.push(`| Credential Format | ${scenario.credentialFormat} |`);
  lines.push(`| Revocation Handling | ${scenario.revocationHandling} |`);
  lines.push("");

  lines.push("## Selected Modules");
  lines.push("");
  if (selectedModules.length === 0) {
    lines.push("_No modules selected._");
  } else {
    for (const mod of selectedModules) {
      lines.push(`- ${mod}`);
    }
  }
  lines.push("");

  // Top risks
  lines.push("## Top Risks");
  lines.push("");
  if (model.summary.topRisks.length === 0) {
    lines.push("_No applicable risks identified._");
  } else {
    for (const risk of model.summary.topRisks) {
      lines.push(
        `- **[${risk.severity.toUpperCase()}]** ${risk.title} — ${risk.why}`
      );
    }
  }
  lines.push("");

  // Assumptions
  lines.push("## Assumptions");
  lines.push("");
  for (const a of model.summary.assumptions) {
    lines.push(`- ${a}`);
  }
  lines.push("");

  // Out of scope
  lines.push("## Out of Scope");
  lines.push("");
  for (const o of model.summary.outOfScope) {
    lines.push(`- ${o}`);
  }
  lines.push("");

  // Warnings
  if (model.warnings.length > 0) {
    lines.push("## Warnings");
    lines.push("");
    for (const w of model.warnings) {
      lines.push(`> ${w}`);
    }
    lines.push("");
  }

  // Checklist by category
  lines.push("## Threat Checklist");
  lines.push("");

  for (const group of model.checklist) {
    const label =
      THREAT_CATEGORY_LABELS[group.category] ?? group.category;
    lines.push(`### ${label}`);
    lines.push("");

    for (const item of group.items) {
      const checkmark = item.applicable ? "x" : " ";
      const severityTag = `[${item.severity.toUpperCase()}]`;
      lines.push(`- [${checkmark}] **${severityTag}** ${item.title}`);

      if (item.applicable) {
        lines.push(`  - Why: ${item.whyApplicable}`);
        lines.push(`  - Risk if unmitigated: ${item.riskIfUnmitigated}`);

        if (item.mitigations.length > 0) {
          lines.push("  - Mitigations:");
          for (const m of item.mitigations) {
            const status = m.satisfied ? "SATISFIED" : "UNSATISFIED";
            lines.push(`    - ${m.title} — **${status}** (${m.how})`);
          }
        }

        if (item.detectionSignals.length > 0) {
          lines.push("  - Detection signals:");
          for (const sig of item.detectionSignals) {
            lines.push(`    - ${sig}`);
          }
        }
      }
      lines.push("");
    }
  }

  lines.push("---");
  lines.push("");
  lines.push(
    "_This threat model is a checklist-based assessment, not a formal security proof. It identifies potential risks based on the configured scenario and selected modules. Review with your security team before deployment._"
  );
  lines.push("");

  return lines.join("\n");
}

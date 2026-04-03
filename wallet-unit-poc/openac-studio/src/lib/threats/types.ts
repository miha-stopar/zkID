import type { Scenario } from "../scenario/schema";

export const THREAT_CATEGORIES = [
  "soundness_forgery",
  "zero_knowledge_leakage",
  "unlinkability_linkability",
  "replay_double_spend",
  "device_sharing_cloning",
  "issuer_tracking_registry",
  "verifier_collusion",
  "dependency_status_revocation",
  "implementation_side_channels",
  "operational_key_management",
] as const;

export type ThreatCategory = (typeof THREAT_CATEGORIES)[number];

export const THREAT_CATEGORY_LABELS: Record<ThreatCategory, string> = {
  soundness_forgery: "Soundness / Forgery",
  zero_knowledge_leakage: "Zero-Knowledge Leakage",
  unlinkability_linkability: "Unlinkability / Linkability",
  replay_double_spend: "Replay / Double-Spend",
  device_sharing_cloning: "Device Sharing / Cloning",
  issuer_tracking_registry: "Issuer Tracking / Registry",
  verifier_collusion: "Verifier Collusion",
  dependency_status_revocation: "Dependency / Status / Revocation",
  implementation_side_channels: "Implementation / Side-Channels",
  operational_key_management: "Operational / Key Management",
};

export interface Mitigation {
  id: string;
  title: string;
  description: string;
  dependsOnModules: string[];
}

export interface ThreatTemplate {
  id: string;
  title: string;
  category: ThreatCategory;
  description: string;
  appliesWhen: (scenario: Scenario, selectedModules: string[]) => boolean;
  severity: "low" | "medium" | "high";
  mitigations: Mitigation[];
  detectionSignals: string[];
  references: string[];
}

export interface ThreatChecklistItem {
  threatId: string;
  title: string;
  severity: string;
  applicable: boolean;
  selected: boolean;
  whyApplicable: string;
  mitigations: {
    id: string;
    title: string;
    satisfied: boolean;
    how: string;
  }[];
  riskIfUnmitigated: string;
  detectionSignals: string[];
}

export interface ThreatCategoryChecklist {
  category: ThreatCategory;
  items: ThreatChecklistItem[];
}

export interface ThreatModelSummary {
  topRisks: { id: string; title: string; severity: string; why: string }[];
  assumptions: string[];
  outOfScope: string[];
}

export interface ThreatModel {
  summary: ThreatModelSummary;
  checklist: ThreatCategoryChecklist[];
  warnings: string[];
}

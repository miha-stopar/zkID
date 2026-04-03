import { z } from "zod";

export const ScenarioSchema = z.object({
  presentationFrequency: z.enum(["one_time", "repeat"]),
  verifierTopology: z.enum(["single_verifier", "multi_verifier_possible_collusion"]),
  unlinkabilityGoal: z.enum(["none", "same_verifier_sessions", "cross_verifiers"]),
  antiReplay: z.enum(["none", "nonce_only", "nullifier"]),
  deviceBinding: z.enum(["none", "recommended", "required"]),
  verificationTarget: z.enum(["offchain", "onchain", "both"]),
  credentialFormat: z.enum(["sd_jwt", "mdoc", "other"]),
  revocationHandling: z.enum(["none", "out_of_band", "in_proof_future"]),
  notes: z.string().optional(),
});

export type Scenario = z.infer<typeof ScenarioSchema>;

export const SCENARIO_FIELD_LABELS: Record<keyof Omit<Scenario, "notes">, string> = {
  presentationFrequency: "Presentation Frequency",
  verifierTopology: "Verifier Topology",
  unlinkabilityGoal: "Unlinkability Goal",
  antiReplay: "Anti-Replay",
  deviceBinding: "Device Binding",
  verificationTarget: "Verification Target",
  credentialFormat: "Credential Format",
  revocationHandling: "Revocation Handling",
};

export const SCENARIO_OPTIONS: Record<keyof Omit<Scenario, "notes">, { value: string; label: string }[]> = {
  presentationFrequency: [
    { value: "one_time", label: "One-time" },
    { value: "repeat", label: "Repeat" },
  ],
  verifierTopology: [
    { value: "single_verifier", label: "Single Verifier" },
    { value: "multi_verifier_possible_collusion", label: "Multi-Verifier (Possible Collusion)" },
  ],
  unlinkabilityGoal: [
    { value: "none", label: "None" },
    { value: "same_verifier_sessions", label: "Same-Verifier Sessions" },
    { value: "cross_verifiers", label: "Cross-Verifiers" },
  ],
  antiReplay: [
    { value: "none", label: "None" },
    { value: "nonce_only", label: "Nonce Only" },
    { value: "nullifier", label: "Nullifier" },
  ],
  deviceBinding: [
    { value: "none", label: "None" },
    { value: "recommended", label: "Recommended" },
    { value: "required", label: "Required" },
  ],
  verificationTarget: [
    { value: "offchain", label: "Off-chain" },
    { value: "onchain", label: "On-chain" },
    { value: "both", label: "Both (Off-chain + On-chain)" },
  ],
  credentialFormat: [
    { value: "sd_jwt", label: "SD-JWT" },
    { value: "mdoc", label: "mDOC" },
    { value: "other", label: "Other" },
  ],
  revocationHandling: [
    { value: "none", label: "None" },
    { value: "out_of_band", label: "Out-of-Band" },
    { value: "in_proof_future", label: "In-Proof (Future)" },
  ],
};

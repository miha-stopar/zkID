import type { Scenario } from "./schema";

export const DEFAULT_SCENARIO: Scenario = {
  presentationFrequency: "one_time",
  verifierTopology: "single_verifier",
  unlinkabilityGoal: "none",
  antiReplay: "nonce_only",
  deviceBinding: "none",
  verificationTarget: "offchain",
  credentialFormat: "sd_jwt",
  revocationHandling: "none",
  notes: "",
};

export const EXAMPLE_SCENARIOS: Record<string, { name: string; scenario: Scenario }> = {
  bbs_platform: {
    name: "One-time BBS Platform Verification",
    scenario: {
      presentationFrequency: "one_time",
      verifierTopology: "single_verifier",
      unlinkabilityGoal: "none",
      antiReplay: "nonce_only",
      deviceBinding: "none",
      verificationTarget: "offchain",
      credentialFormat: "sd_jwt",
      revocationHandling: "none",
      notes: "One-time BBS platform credential verification – off-chain, no device binding needed.",
    },
  },
  repeat_alcohol: {
    name: "Repeat Presentations (Buy Alcohol)",
    scenario: {
      presentationFrequency: "repeat",
      verifierTopology: "multi_verifier_possible_collusion",
      unlinkabilityGoal: "cross_verifiers",
      antiReplay: "nullifier",
      deviceBinding: "required",
      verificationTarget: "offchain",
      credentialFormat: "sd_jwt",
      revocationHandling: "out_of_band",
      notes: "Age check at different stores – must be unlinkable across verifiers, device binding required.",
    },
  },
};

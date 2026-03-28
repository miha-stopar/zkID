import type { Rule } from "./types";

export const RULESET: Rule[] = [
  // Always-on modules
  {
    id: "always_issuer_sig",
    description: "Always include issuer signature verification",
    predicate: () => true,
    moduleAdds: ["issuer_sig_verify"],
    moduleRemovals: [],
    explanation: () => "Issuer signature verification is always required to ensure credential authenticity.",
  },
  {
    id: "always_commitments",
    description: "Always include attribute commitments",
    predicate: () => true,
    moduleAdds: ["attribute_commitments"],
    moduleRemovals: [],
    explanation: () => "Attribute commitments are always required for privacy-preserving proofs.",
  },
  {
    id: "always_selective_disclosure",
    description: "Always include selective disclosure",
    predicate: () => true,
    moduleAdds: ["selective_disclosure"],
    moduleRemovals: [],
    explanation: () => "Selective disclosure is always included to support data minimization.",
  },
  {
    id: "always_prepare_show",
    description: "Always include prepare/show split",
    predicate: () => true,
    moduleAdds: ["prepare_show_split"],
    moduleRemovals: [],
    explanation: () => "Prepare/show split is included for protocol structure (offline preparation, online showing).",
  },
  // Conditional: reblind/rerandomize
  {
    id: "reblind_for_repeat",
    description: "Add reblind if repeat presentations or unlinkability needed",
    predicate: (s) => s.presentationFrequency === "repeat" || s.unlinkabilityGoal !== "none",
    moduleAdds: ["reblind_rerandomize"],
    moduleRemovals: [],
    explanation: (s) => {
      const reasons: string[] = [];
      if (s.presentationFrequency === "repeat") {
        reasons.push("repeat presentations require rerandomization to prevent cross-session linkage");
      }
      if (s.unlinkabilityGoal !== "none") {
        reasons.push(`unlinkability goal '${s.unlinkabilityGoal}' requires reblinding to prevent verifier correlation`);
      }
      return `Reblind/rerandomize added: ${reasons.join("; ")}.`;
    },
  },
  // Conditional: verifier challenge nonce
  {
    id: "nonce_unless_no_antireplay",
    description: "Add verifier challenge nonce unless anti-replay is none",
    predicate: (s) => s.antiReplay !== "none",
    moduleAdds: ["verifier_challenge_nonce"],
    moduleRemovals: [],
    explanation: (s) =>
      `Verifier challenge nonce added: anti-replay is '${s.antiReplay}', requiring freshness guarantee.`,
  },
  // Conditional: nullifier
  {
    id: "nullifier_for_nullifier_mode",
    description: "Add nullifier anti-replay when nullifier mode selected",
    predicate: (s) => s.antiReplay === "nullifier",
    moduleAdds: ["nullifier_antireplay"],
    moduleRemovals: [],
    explanation: () =>
      "Nullifier anti-replay added: prevents double-use via deterministic nullifier without revealing identity.",
  },
  // Conditional: device binding
  {
    id: "device_binding_required",
    description: "Add device binding when required or for repeat presentations",
    predicate: (s) => s.deviceBinding === "required" || s.presentationFrequency === "repeat",
    moduleAdds: ["device_binding"],
    moduleRemovals: [],
    explanation: (s) => {
      if (s.presentationFrequency === "repeat" && s.deviceBinding !== "required") {
        return "Device binding added: repeat presentations require device binding to prevent credential sharing across sessions.";
      }
      return "Device binding added: credential presentation is bound to hardware key for possession proof.";
    },
  },
  // Verification target rules
  {
    id: "offchain_target",
    description: "Add off-chain verify for offchain target",
    predicate: (s) => s.verificationTarget === "offchain",
    moduleAdds: ["offchain_verify"],
    moduleRemovals: [],
    explanation: () => "Off-chain verification added: proof verified directly by verifier without blockchain.",
  },
  {
    id: "onchain_target",
    description: "Add on-chain verify for onchain target",
    predicate: (s) => s.verificationTarget === "onchain",
    moduleAdds: ["onchain_verify"],
    moduleRemovals: [],
    explanation: () => "On-chain verification added: proof verified by smart contract on-chain.",
  },
  {
    id: "dual_target",
    description: "Add dual verify + both modules for both target",
    predicate: (s) => s.verificationTarget === "both",
    moduleAdds: ["dual_verify_planB", "offchain_verify", "onchain_verify"],
    moduleRemovals: [],
    explanation: () =>
      "Dual verification added: both off-chain and on-chain paths enabled with on-chain as fallback.",
  },
  // Revocation handling warning
  {
    id: "revocation_future_warning",
    description: "Warn about unimplemented in-proof revocation",
    predicate: (s) => s.revocationHandling === "in_proof_future",
    moduleAdds: [],
    moduleRemovals: [],
    explanation: () =>
      "Warning: In-proof revocation is planned for a future version and is not yet implemented.",
  },
];

import type { ModuleDefinition } from "./types";

export const MODULE_REGISTRY: ModuleDefinition[] = [
  {
    id: "prepare_show_split",
    title: "Prepare / Show Split",
    description: "Splits the credential presentation into a prepare phase (offline) and a show phase (online), enabling pre-computation.",
    provides: ["prepare_show_protocol"],
    requires: [],
    conflicts: [],
    risksIfOmitted: [
      "No separation between offline preparation and online showing",
      "Cannot pre-compute proofs for latency-sensitive presentations",
    ],
    diagramHooks: {
      sequenceSteps: [
        "Wallet->>Wallet: prepare(credential) → pi_prepare",
        "Wallet->>Verifier: show(pi_prepare, disclosed) → pi_show",
      ],
    },
  },
  {
    id: "issuer_sig_verify",
    title: "Issuer Signature Verification",
    description: "Verifies the issuer's digital signature on the credential to ensure authenticity and integrity.",
    provides: ["issuer_authenticity"],
    requires: [],
    conflicts: [],
    risksIfOmitted: [
      "Credential authenticity cannot be verified",
      "Forged credentials may be accepted",
    ],
    diagramHooks: {
      artifacts: ["sig_issuer"],
      sequenceSteps: [
        "Issuer->>Wallet: issue(credential, sig_issuer)",
        "Verifier->>Verifier: verify(sig_issuer, issuer_pk)",
      ],
    },
  },
  {
    id: "attribute_commitments",
    title: "Attribute Commitments",
    description: "Creates cryptographic commitments to credential attributes, enabling selective disclosure without revealing raw values.",
    provides: ["commitments"],
    requires: [],
    conflicts: [],
    risksIfOmitted: [
      "All attributes must be revealed during verification",
      "No privacy-preserving selective disclosure possible",
    ],
    diagramHooks: {
      artifacts: ["C"],
      sequenceSteps: [
        "Wallet->>Wallet: commit(attributes) → C",
      ],
    },
  },
  {
    id: "selective_disclosure",
    title: "Selective Disclosure",
    description: "Allows the holder to reveal only specific attributes from the credential while proving possession of the full credential.",
    provides: ["selective_disclosure"],
    requires: ["commitments"],
    conflicts: [],
    risksIfOmitted: [
      "Holder must reveal all credential attributes to verifier",
      "Violates data minimization principle",
    ],
    diagramHooks: {
      sequenceSteps: [
        "Wallet->>Verifier: disclose(selected_attrs, proof_of_rest)",
      ],
    },
  },
  {
    id: "reblind_rerandomize",
    title: "Reblind / Rerandomize",
    description: "Rerandomizes the credential presentation so that multiple showings cannot be linked by the verifier.",
    provides: ["unlinkability"],
    requires: ["commitments"],
    conflicts: [],
    risksIfOmitted: [
      "Presentations are linkable across sessions",
      "Verifier can correlate multiple showings to the same holder",
      "Cross-verifier tracking possible if colluding",
    ],
    diagramHooks: {
      sequenceSteps: [
        "Wallet->>Wallet: reblind(C, randomness') → C'",
      ],
    },
  },
  {
    id: "verifier_challenge_nonce",
    title: "Verifier Challenge Nonce",
    description: "Verifier provides a fresh nonce (challenge) to prevent replay of old proofs.",
    provides: ["nonce_freshness"],
    requires: [],
    conflicts: [],
    risksIfOmitted: [
      "Old proofs can be replayed",
      "No freshness guarantee for verification session",
    ],
    diagramHooks: {
      artifacts: ["ch"],
      sequenceSteps: [
        "Verifier->>Wallet: challenge(ch)",
        "Wallet->>Verifier: proof(pi, ch)",
      ],
    },
  },
  {
    id: "nullifier_antireplay",
    title: "Nullifier Anti-Replay",
    description: "Generates a deterministic nullifier tied to the credential and context, preventing double-use without revealing identity.",
    provides: ["nullifier", "anti_replay"],
    requires: ["commitments"],
    conflicts: [],
    risksIfOmitted: [
      "Credential can be presented multiple times in contexts requiring single-use",
      "Double-spending or double-voting possible",
    ],
    diagramHooks: {
      artifacts: ["nf"],
      sequenceSteps: [
        "Wallet->>Wallet: nullifier(credential, context) → nf",
        "Wallet->>Verifier: present(proof, nf)",
        "Verifier->>Verifier: check(nf ∉ spent_set)",
      ],
    },
  },
  {
    id: "device_binding",
    title: "Device Binding",
    description: "Binds the credential presentation to a specific device via a hardware-backed key, proving physical possession.",
    provides: ["device_attestation"],
    requires: [],
    conflicts: [],
    risksIfOmitted: [
      "Credential can be used from any device (no possession proof)",
      "Cloned credentials cannot be detected",
    ],
    diagramHooks: {
      artifacts: ["sigma_ch"],
      sequenceSteps: [
        "Wallet->>Wallet: device_sign(ch) → sigma_ch",
        "Wallet->>Verifier: present(proof, sigma_ch)",
        "Verifier->>Verifier: verify(sigma_ch, device_pk)",
      ],
    },
  },
  {
    id: "offchain_verify",
    title: "Off-chain Verification",
    description: "Proof is verified off-chain by the verifier directly, without any blockchain interaction.",
    provides: ["offchain_verification"],
    requires: [],
    conflicts: ["onchain_verify"],
    risksIfOmitted: [
      "No off-chain verification path available",
    ],
    diagramHooks: {
      sequenceSteps: [
        "Verifier->>Verifier: offchain_verify(proof) → accept/reject",
      ],
    },
  },
  {
    id: "onchain_verify",
    title: "On-chain Verification",
    description: "Proof is submitted to and verified by a smart contract on-chain.",
    provides: ["onchain_verification"],
    requires: [],
    conflicts: ["offchain_verify"],
    risksIfOmitted: [
      "No on-chain verification path available",
      "Cannot leverage blockchain for trust or transparency",
    ],
    diagramHooks: {
      actors: ["Chain"],
      sequenceSteps: [
        "Wallet->>Chain: submitProof(proof)",
        "Chain->>Chain: verify(proof) → accept/reject",
      ],
    },
  },
  {
    id: "dual_verify_planB",
    title: "Dual Verification (Plan B)",
    description: "Supports both off-chain and on-chain verification paths, with on-chain as a fallback or additional trust anchor.",
    provides: ["dual_verification"],
    requires: [],
    conflicts: [],
    risksIfOmitted: [
      "No fallback verification path",
      "Single point of verification failure",
    ],
    diagramHooks: {
      actors: ["Chain"],
      sequenceSteps: [
        "Verifier->>Verifier: offchain_verify(proof)",
        "Verifier-->>Chain: optional: anchor(proof_hash)",
      ],
    },
  },
];

export function getModule(id: string): ModuleDefinition | undefined {
  return MODULE_REGISTRY.find((m) => m.id === id);
}

export function getModulesByIds(ids: string[]): ModuleDefinition[] {
  return ids.map((id) => getModule(id)).filter((m): m is ModuleDefinition => m !== undefined);
}

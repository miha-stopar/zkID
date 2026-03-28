import type { ThreatTemplate } from "./types";

export const THREAT_TEMPLATES: ThreatTemplate[] = [
  // ── soundness_forgery ──────────────────────────────────────────────
  {
    id: "T-SF-01",
    title: "Credential forgery via missing issuer signature verification",
    category: "soundness_forgery",
    description:
      "Without verifying the issuer's signature, an attacker can forge credentials and present them as authentic.",
    appliesWhen: (_s, mods) => !mods.includes("issuer_sig_verify"),
    severity: "high",
    mitigations: [
      {
        id: "M-SF-01a",
        title: "Enable issuer signature verification",
        description: "Include the issuer_sig_verify module so the verifier checks the issuer's signature on every presentation.",
        dependsOnModules: ["issuer_sig_verify"],
      },
    ],
    detectionSignals: [
      "Verifier accepts proofs without checking sig_issuer",
      "No issuer public key validation in verification flow",
    ],
    references: [
      "NIST SP 800-63C: Assertion verification requirements",
      "OpenAC design: issuer authenticity is a mandatory baseline",
    ],
  },
  {
    id: "T-SF-02",
    title: "Selective disclosure proof soundness failure",
    category: "soundness_forgery",
    description:
      "If attribute commitments are absent, selective disclosure cannot be cryptographically enforced. A holder could claim arbitrary attribute values.",
    appliesWhen: (_s, mods) =>
      !mods.includes("attribute_commitments") && mods.includes("selective_disclosure"),
    severity: "high",
    mitigations: [
      {
        id: "M-SF-02a",
        title: "Include attribute commitments",
        description: "Attribute commitments provide the binding between disclosed attributes and the credential.",
        dependsOnModules: ["attribute_commitments"],
      },
    ],
    detectionSignals: [
      "Selective disclosure used without underlying commitment scheme",
      "Verifier cannot verify attribute binding",
    ],
    references: [
      "Camenisch-Lysyanskaya signature scheme: commitment-based selective disclosure",
    ],
  },

  // ── zero_knowledge_leakage ─────────────────────────────────────────
  {
    id: "T-ZK-01",
    title: "Attribute over-disclosure due to missing selective disclosure",
    category: "zero_knowledge_leakage",
    description:
      "Without selective disclosure, the holder must reveal all credential attributes to the verifier, violating data minimization.",
    appliesWhen: (_s, mods) => !mods.includes("selective_disclosure"),
    severity: "high",
    mitigations: [
      {
        id: "M-ZK-01a",
        title: "Enable selective disclosure",
        description: "Include selective_disclosure module to reveal only required attributes.",
        dependsOnModules: ["selective_disclosure"],
      },
    ],
    detectionSignals: [
      "Full credential payload transmitted to verifier",
      "No attribute filtering in presentation protocol",
    ],
    references: [
      "GDPR Article 5(1)(c): Data minimization principle",
      "SD-JWT specification: selective disclosure claims",
    ],
  },

  // ── unlinkability_linkability ──────────────────────────────────────
  {
    id: "T-UL-01",
    title: "Cross-session linkability without reblind/rerandomize",
    category: "unlinkability_linkability",
    description:
      "When unlinkability is required but reblind is missing, verifiers can correlate presentations across sessions using stable proof elements.",
    appliesWhen: (s, mods) =>
      s.unlinkabilityGoal !== "none" && !mods.includes("reblind_rerandomize"),
    severity: "high",
    mitigations: [
      {
        id: "M-UL-01a",
        title: "Enable reblind/rerandomize",
        description: "Rerandomize credential presentations so each showing produces a fresh, unlinkable proof.",
        dependsOnModules: ["reblind_rerandomize"],
      },
    ],
    detectionSignals: [
      "Same commitment values appear across multiple presentations",
      "Verifier can match proof transcripts between sessions",
    ],
    references: [
      "Brands blind signatures: rerandomization for unlinkability",
      "OpenAC unlinkability design: reblind as core privacy primitive",
    ],
  },
  {
    id: "T-UL-02",
    title: "Cross-verifier linkability in multi-verifier topology",
    category: "unlinkability_linkability",
    description:
      "In multi-verifier scenarios, without rerandomization, colluding verifiers can link presentations to the same holder.",
    appliesWhen: (s, mods) =>
      s.verifierTopology === "multi_verifier_possible_collusion" &&
      !mods.includes("reblind_rerandomize"),
    severity: "high",
    mitigations: [
      {
        id: "M-UL-02a",
        title: "Enable reblind/rerandomize",
        description: "Each presentation to a different verifier uses fresh randomness, preventing cross-verifier correlation.",
        dependsOnModules: ["reblind_rerandomize"],
      },
    ],
    detectionSignals: [
      "Multiple verifiers receive identical proof structure",
      "Stable identifier or commitment shared across verifiers",
    ],
    references: [
      "OpenAC cross-verifier unlinkability: reblind requirement for multi-verifier topologies",
    ],
  },
  {
    id: "T-UL-03",
    title: "Repeat presentation linkability",
    category: "unlinkability_linkability",
    description:
      "Repeat presentations without rerandomization allow a verifier to build a profile of the holder across visits.",
    appliesWhen: (s, mods) =>
      s.presentationFrequency === "repeat" && !mods.includes("reblind_rerandomize"),
    severity: "medium",
    mitigations: [
      {
        id: "M-UL-03a",
        title: "Enable reblind/rerandomize",
        description: "Rerandomize each repeated presentation so successive visits are unlinkable.",
        dependsOnModules: ["reblind_rerandomize"],
      },
    ],
    detectionSignals: [
      "Verifier logs show repeated identical proof fingerprints",
      "Temporal correlation of presentations from same commitment",
    ],
    references: [
      "OpenAC repeat presentation design: unlinkability across sessions",
    ],
  },

  // ── replay_double_spend ────────────────────────────────────────────
  {
    id: "T-RP-01",
    title: "Replay attack without nonce freshness",
    category: "replay_double_spend",
    description:
      "Without a verifier challenge nonce, an attacker can capture and replay a valid proof to impersonate the holder.",
    appliesWhen: (s, mods) =>
      s.antiReplay !== "none" && !mods.includes("verifier_challenge_nonce"),
    severity: "high",
    mitigations: [
      {
        id: "M-RP-01a",
        title: "Include verifier challenge nonce",
        description: "Verifier provides a fresh nonce per session that is bound into the proof, preventing replay.",
        dependsOnModules: ["verifier_challenge_nonce"],
      },
    ],
    detectionSignals: [
      "Proofs accepted without session-bound challenge",
      "No freshness check on verification side",
    ],
    references: [
      "Challenge-response protocols: nonce binding for replay prevention",
    ],
  },
  {
    id: "T-RP-02",
    title: "Double-use without nullifier",
    category: "replay_double_spend",
    description:
      "When nullifier anti-replay is required but the nullifier module is missing, the same credential can be presented multiple times in contexts requiring single-use.",
    appliesWhen: (s, mods) =>
      s.antiReplay === "nullifier" && !mods.includes("nullifier_antireplay"),
    severity: "high",
    mitigations: [
      {
        id: "M-RP-02a",
        title: "Include nullifier module",
        description: "Generate a deterministic nullifier per credential+context so the verifier can detect double-use.",
        dependsOnModules: ["nullifier_antireplay"],
      },
    ],
    detectionSignals: [
      "No nullifier generated or checked during presentation",
      "Spent-set / double-use registry absent",
    ],
    references: [
      "Zcash nullifier design: deterministic double-spend prevention",
      "OpenAC anti-replay: nullifier as single-use enforcement",
    ],
  },
  {
    id: "T-RP-03",
    title: "Weak nonce handling enabling targeted replay",
    category: "replay_double_spend",
    description:
      "Even with a nonce module present, if nonces are predictable, short, or reused, targeted replay attacks remain feasible.",
    appliesWhen: (s, mods) =>
      s.antiReplay !== "none" && mods.includes("verifier_challenge_nonce"),
    severity: "low",
    mitigations: [
      {
        id: "M-RP-03a",
        title: "Ensure cryptographically random nonces",
        description: "Use at least 128-bit random nonces generated by a CSPRNG, never reused.",
        dependsOnModules: ["verifier_challenge_nonce"],
      },
    ],
    detectionSignals: [
      "Nonce entropy below 128 bits",
      "Nonce reuse observed in session logs",
    ],
    references: [
      "NIST SP 800-90A: Random number generation",
    ],
  },

  // ── device_sharing_cloning ─────────────────────────────────────────
  {
    id: "T-DS-01",
    title: "Device sharing / credential cloning without device binding",
    category: "device_sharing_cloning",
    description:
      "When device binding is required but missing, credentials can be exported and used from any device, enabling sharing or cloning attacks.",
    appliesWhen: (s, mods) =>
      s.deviceBinding === "required" && !mods.includes("device_binding"),
    severity: "high",
    mitigations: [
      {
        id: "M-DS-01a",
        title: "Enable device binding module",
        description: "Bind credential presentations to a hardware-backed key so only the original device can present.",
        dependsOnModules: ["device_binding"],
      },
    ],
    detectionSignals: [
      "Credential used from multiple device fingerprints",
      "No device attestation in proof",
    ],
    references: [
      "FIDO2/WebAuthn: hardware-backed key attestation",
      "OpenAC device binding: proof of possession via device key",
    ],
  },
  {
    id: "T-DS-02",
    title: "Optional device binding bypass",
    category: "device_sharing_cloning",
    description:
      "Device binding is recommended but not enforced. Users may skip it, leaving credentials vulnerable to sharing.",
    appliesWhen: (s, mods) =>
      s.deviceBinding === "recommended" && !mods.includes("device_binding"),
    severity: "medium",
    mitigations: [
      {
        id: "M-DS-02a",
        title: "Enable device binding module",
        description: "Include device binding to enforce possession proof even when policy recommends (not requires) it.",
        dependsOnModules: ["device_binding"],
      },
    ],
    detectionSignals: [
      "Presentations accepted without device attestation when policy recommends it",
    ],
    references: [
      "EU Digital Identity Wallet: device binding recommendations",
    ],
  },

  // ── issuer_tracking_registry ───────────────────────────────────────
  {
    id: "T-IT-01",
    title: "Issuer tracking via stable credential identifiers",
    category: "issuer_tracking_registry",
    description:
      "If the credential contains stable identifiers (e.g., credential ID, serial number) that are revealed during presentation, the issuer can track when and where credentials are used.",
    appliesWhen: (s, _mods) =>
      s.unlinkabilityGoal !== "none",
    severity: "medium",
    mitigations: [
      {
        id: "M-IT-01a",
        title: "Use selective disclosure to hide credential ID",
        description: "Ensure stable identifiers are never disclosed; only derive necessary attributes.",
        dependsOnModules: ["selective_disclosure"],
      },
      {
        id: "M-IT-01b",
        title: "Rerandomize to break issuer correlation",
        description: "Reblinding prevents the issuer from correlating based on commitment values.",
        dependsOnModules: ["reblind_rerandomize"],
      },
    ],
    detectionSignals: [
      "Credential serial or ID field included in disclosed attributes",
      "Issuer can query verifier logs by credential identifier",
    ],
    references: [
      "W3C Verifiable Credentials: privacy considerations for credential identifiers",
      "OpenAC issuer minimization: avoid stable IDs in disclosures",
    ],
  },
  {
    id: "T-IT-02",
    title: "Registry-based issuer tracking",
    category: "issuer_tracking_registry",
    description:
      "If the verifier must contact the issuer or a registry to validate the credential (e.g., revocation check), the issuer can log usage patterns and track the holder.",
    appliesWhen: (s) =>
      s.revocationHandling === "out_of_band",
    severity: "medium",
    mitigations: [
      {
        id: "M-IT-02a",
        title: "Prefer in-proof revocation checks",
        description: "In-proof status verification avoids contacting the issuer at presentation time.",
        dependsOnModules: [],
      },
    ],
    detectionSignals: [
      "Verifier contacts issuer/registry during each presentation",
      "Issuer revocation endpoint logs include credential identifiers",
    ],
    references: [
      "Privacy-preserving revocation: accumulator-based approaches",
      "OpenAC revocation strategy: in-proof future vs out-of-band trade-offs",
    ],
  },

  // ── verifier_collusion ─────────────────────────────────────────────
  {
    id: "T-VC-01",
    title: "Verifier collusion without rerandomization",
    category: "verifier_collusion",
    description:
      "Without reblind, multiple verifiers can share proof transcripts and link presentations to the same holder, even without the holder's knowledge.",
    appliesWhen: (s, mods) =>
      s.verifierTopology === "multi_verifier_possible_collusion" &&
      !mods.includes("reblind_rerandomize"),
    severity: "high",
    mitigations: [
      {
        id: "M-VC-01a",
        title: "Enable reblind/rerandomize",
        description: "Each verifier sees a fresh, rerandomized proof that cannot be correlated with proofs shown to other verifiers.",
        dependsOnModules: ["reblind_rerandomize"],
      },
    ],
    detectionSignals: [
      "Identical proof components observed by different verifiers",
      "Verifiers share a common database of proof transcripts",
    ],
    references: [
      "OpenAC verifier collusion model: reblind as primary defense",
    ],
  },
  {
    id: "T-VC-02",
    title: "Residual collusion risk via disclosed attributes",
    category: "verifier_collusion",
    description:
      "Even with rerandomization, if the same rare attribute combination is disclosed to colluding verifiers, statistical re-identification is possible.",
    appliesWhen: (s, mods) =>
      s.verifierTopology === "multi_verifier_possible_collusion" &&
      mods.includes("reblind_rerandomize"),
    severity: "low",
    mitigations: [
      {
        id: "M-VC-02a",
        title: "Minimize disclosed attributes",
        description: "Disclose only the minimum attributes needed per verifier to reduce re-identification surface.",
        dependsOnModules: ["selective_disclosure"],
      },
    ],
    detectionSignals: [
      "Same rare attribute set disclosed to multiple verifiers",
      "Small anonymity set for disclosed attribute combination",
    ],
    references: [
      "k-anonymity in attribute disclosure: minimization strategies",
    ],
  },

  // ── dependency_status_revocation ────────────────────────────────────
  {
    id: "T-DR-01",
    title: "No revocation handling configured",
    category: "dependency_status_revocation",
    description:
      "Without any revocation mechanism, compromised or expired credentials cannot be invalidated and may be used indefinitely.",
    appliesWhen: (s) => s.revocationHandling === "none",
    severity: "medium",
    mitigations: [
      {
        id: "M-DR-01a",
        title: "Configure revocation handling",
        description: "Choose either out-of-band or in-proof revocation to enable credential invalidation.",
        dependsOnModules: [],
      },
    ],
    detectionSignals: [
      "No revocation list or accumulator configured",
      "Expired credentials still accepted by verifiers",
    ],
    references: [
      "W3C VC status methods: RevocationList2020, StatusList2021",
      "OpenAC revocation design considerations",
    ],
  },
  {
    id: "T-DR-02",
    title: "In-proof revocation not yet implemented",
    category: "dependency_status_revocation",
    description:
      "In-proof revocation is selected but marked as future work. Until implemented, there is no active revocation enforcement.",
    appliesWhen: (s) => s.revocationHandling === "in_proof_future",
    severity: "medium",
    mitigations: [
      {
        id: "M-DR-02a",
        title: "Use out-of-band revocation as interim",
        description: "Until in-proof revocation is available, configure out-of-band checks as a temporary measure.",
        dependsOnModules: [],
      },
    ],
    detectionSignals: [
      "revocationHandling set to in_proof_future but no accumulator logic present",
      "No runtime revocation check in verification flow",
    ],
    references: [
      "Cryptographic accumulators for revocation: Camenisch-Lysyanskaya, RSA accumulators",
    ],
  },

  // ── implementation_side_channels ────────────────────────────────────
  {
    id: "T-SC-01",
    title: "Mobile prover side-channel risks",
    category: "implementation_side_channels",
    description:
      "ZK proof generation on mobile devices may leak information through timing variations, memory access patterns, or system logs.",
    appliesWhen: () => true,
    severity: "low",
    mitigations: [
      {
        id: "M-SC-01a",
        title: "Use constant-time implementations",
        description: "Ensure cryptographic operations use constant-time algorithms to prevent timing side-channels.",
        dependsOnModules: [],
      },
    ],
    detectionSignals: [
      "Variable proof generation time correlated with attribute values",
      "Sensitive data in system logs or crash reports",
    ],
    references: [
      "OWASP Mobile: M9 - Reverse Engineering",
      "Side-channel resistant implementations for mobile ZK provers",
    ],
  },
  {
    id: "T-SC-02",
    title: "Logging or debugging leakage of credential data",
    category: "implementation_side_channels",
    description:
      "Debug logging in production may inadvertently output credential attributes, proofs, or secret keys to logs accessible by third parties.",
    appliesWhen: () => true,
    severity: "low",
    mitigations: [
      {
        id: "M-SC-02a",
        title: "Strip sensitive data from production logs",
        description: "Ensure no credential attributes, private keys, or proof internals are logged in production builds.",
        dependsOnModules: [],
      },
    ],
    detectionSignals: [
      "Credential data found in application logs",
      "Proof parameters visible in network debugging tools",
    ],
    references: [
      "OWASP logging cheat sheet: sensitive data handling",
    ],
  },

  // ── operational_key_management ──────────────────────────────────────
  {
    id: "T-OK-01",
    title: "On-chain verification constraints and risks",
    category: "operational_key_management",
    description:
      "On-chain verification introduces operational risks: proof size must fit gas limits, verifier contract must be audited, and verification key management becomes critical.",
    appliesWhen: (s) =>
      s.verificationTarget === "onchain" || s.verificationTarget === "both",
    severity: "medium",
    mitigations: [
      {
        id: "M-OK-01a",
        title: "Audit verifier smart contract",
        description: "Ensure the on-chain verifier contract is formally verified or audited for correctness.",
        dependsOnModules: ["onchain_verify"],
      },
      {
        id: "M-OK-01b",
        title: "Validate proof size within gas limits",
        description: "Confirm that proof serialization and verification fit within target chain gas constraints.",
        dependsOnModules: ["onchain_verify"],
      },
    ],
    detectionSignals: [
      "Proof verification exceeds block gas limit",
      "Unaudited verifier contract deployed to mainnet",
      "Verification key mismatch between prover and on-chain verifier",
    ],
    references: [
      "EVM gas considerations for ZK proof verification (Groth16, PLONK)",
      "OpenAC on-chain verification: operational risk checklist",
    ],
  },
  {
    id: "T-OK-02",
    title: "Issuer key compromise without rotation",
    category: "operational_key_management",
    description:
      "If the issuer's signing key is compromised and no key rotation mechanism exists, all previously issued credentials remain trusted and new forged credentials can be created.",
    appliesWhen: () => true,
    severity: "medium",
    mitigations: [
      {
        id: "M-OK-02a",
        title: "Implement issuer key rotation plan",
        description: "Define key rotation procedures and publish updated issuer public keys via a trusted registry.",
        dependsOnModules: [],
      },
    ],
    detectionSignals: [
      "Single issuer key used indefinitely without rotation schedule",
      "No key revocation mechanism for issuer keys",
    ],
    references: [
      "NIST SP 800-57: Key management lifecycle",
      "DID document key rotation practices",
    ],
  },
];

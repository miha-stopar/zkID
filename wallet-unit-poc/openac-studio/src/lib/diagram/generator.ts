import type { DiagramLevel, DiagramOutput } from "./types";
import { getModulesByIds } from "../modules/registry";
import type { ModuleDefinition } from "../modules/types";

function hasModule(modules: ModuleDefinition[], id: string): boolean {
  return modules.some((m) => m.id === id);
}

export function generateDiagram(moduleIds: string[], level: DiagramLevel): DiagramOutput {
  const modules = getModulesByIds(moduleIds);

  if (level === "high_level") {
    return { level, mermaid: generateHighLevel(modules) };
  }
  return { level, mermaid: generateCryptoLevel(modules) };
}

function generateHighLevel(modules: ModuleDefinition[]): string {
  const hasChain =
    hasModule(modules, "onchain_verify") || hasModule(modules, "dual_verify_planB");

  const lines: string[] = ["sequenceDiagram"];

  // Actors
  lines.push("    participant I as Issuer");
  lines.push("    participant W as Wallet");
  lines.push("    participant V as Verifier");
  if (hasChain) {
    lines.push("    participant C as Chain");
  }

  lines.push("");

  // Device key registration (before issuance)
  if (hasModule(modules, "device_binding")) {
    lines.push("    W->>W: Generate device key pair");
    lines.push("    W->>I: Register device public key");
  }

  // Issuance
  if (hasModule(modules, "issuer_sig_verify")) {
    if (hasModule(modules, "device_binding")) {
      lines.push("    I->>W: Issue credential + signature (bound to device key)");
    } else {
      lines.push("    I->>W: Issue credential + signature");
    }
  }

  // Preparation
  if (hasModule(modules, "attribute_commitments")) {
    lines.push("    W->>W: Create attribute commitments");
  }
  if (hasModule(modules, "reblind_rerandomize")) {
    lines.push("    W->>W: Reblind / rerandomize");
  }
  if (hasModule(modules, "selective_disclosure")) {
    lines.push("    W->>W: Select attributes to disclose");
  }

  // Challenge
  if (hasModule(modules, "verifier_challenge_nonce")) {
    lines.push("    V->>W: Send challenge nonce");
  }

  // Presentation
  if (hasModule(modules, "device_binding")) {
    lines.push("    W->>W: Sign challenge with device key");
  }
  if (hasModule(modules, "nullifier_antireplay")) {
    lines.push("    W->>W: Compute nullifier");
  }
  if (hasModule(modules, "prepare_show_split")) {
    lines.push("    W->>V: Present proof (prepare/show)");
  }

  // Verification
  if (hasModule(modules, "issuer_sig_verify")) {
    lines.push("    V->>V: Verify issuer signature");
  }
  if (hasModule(modules, "device_binding")) {
    lines.push("    V->>V: Verify device signature");
  }
  if (hasModule(modules, "nullifier_antireplay")) {
    lines.push("    V->>V: Check nullifier not spent");
  }
  if (hasModule(modules, "offchain_verify")) {
    lines.push("    V->>V: Off-chain verification → accept/reject");
  }
  if (hasModule(modules, "onchain_verify")) {
    lines.push("    W->>C: Submit proof on-chain");
    lines.push("    C->>C: On-chain verification → accept/reject");
  }
  if (hasModule(modules, "dual_verify_planB")) {
    lines.push("    V-->>C: Optional: anchor proof hash on-chain");
  }

  return lines.join("\n");
}

function generateCryptoLevel(modules: ModuleDefinition[]): string {
  const hasChain =
    hasModule(modules, "onchain_verify") || hasModule(modules, "dual_verify_planB");

  const lines: string[] = ["sequenceDiagram"];

  // Actors
  lines.push("    participant I as Issuer");
  lines.push("    participant W as Wallet");
  lines.push("    participant V as Verifier");
  if (hasChain) {
    lines.push("    participant C as Chain");
  }

  lines.push("");

  // Device key registration (before issuance)
  if (hasModule(modules, "device_binding")) {
    lines.push("    W->>W: (dsk, dpk) = KeyGen()");
    lines.push("    W->>I: Register(dpk)");
  }

  // Issuance
  if (hasModule(modules, "issuer_sig_verify")) {
    if (hasModule(modules, "device_binding")) {
      lines.push("    I->>W: credential, sig_issuer = Sign(isk, credential || dpk)");
    } else {
      lines.push("    I->>W: credential, sig_issuer = Sign(isk, credential)");
    }
  }

  // Commitments
  if (hasModule(modules, "attribute_commitments")) {
    lines.push("    W->>W: C = Commit(attributes, r)");
  }

  // Reblind
  if (hasModule(modules, "reblind_rerandomize")) {
    lines.push("    W->>W: C' = Reblind(C, r')");
    lines.push("    Note over W: Fresh randomness r' ensures unlinkability");
  }

  // Selective disclosure
  if (hasModule(modules, "selective_disclosure")) {
    lines.push("    W->>W: pi_selective = ProveSubset(C, disclosed_attrs)");
  }

  // Challenge
  if (hasModule(modules, "verifier_challenge_nonce")) {
    lines.push("    V->>W: ch = RandomNonce()");
  }

  // Prepare/Show
  if (hasModule(modules, "prepare_show_split")) {
    lines.push("    W->>W: pi_prepare = Prepare(C', sig_issuer)");
    lines.push("    W->>V: pi_show = Show(pi_prepare, ch, disclosed_attrs)");
  }

  // Device binding
  if (hasModule(modules, "device_binding")) {
    lines.push("    W->>W: sigma_ch = DeviceSign(dsk, ch)");
    lines.push("    W->>V: sigma_ch");
  }

  // Nullifier
  if (hasModule(modules, "nullifier_antireplay")) {
    lines.push("    W->>W: nf = PRF(nsk, context)");
    lines.push("    W->>V: nf");
  }

  // Verification
  if (hasModule(modules, "issuer_sig_verify")) {
    lines.push("    V->>V: Verify(ipk, pi_show) = 1?");
  }
  if (hasModule(modules, "device_binding")) {
    lines.push("    V->>V: Verify(dpk, sigma_ch, ch) = 1?");
  }
  if (hasModule(modules, "nullifier_antireplay")) {
    lines.push("    V->>V: Assert(nf ∉ spent_set)");
  }
  if (hasModule(modules, "offchain_verify")) {
    lines.push("    V->>V: result = OffchainVerify(pi_show)");
  }
  if (hasModule(modules, "onchain_verify")) {
    lines.push("    W->>C: tx = SubmitProof(pi_show)");
    lines.push("    C->>C: result = OnchainVerify(pi_show)");
  }
  if (hasModule(modules, "dual_verify_planB")) {
    lines.push("    V-->>C: Anchor(hash(pi_show))");
  }

  return lines.join("\n");
}

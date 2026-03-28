import { describe, it, expect } from "vitest";
import { generateDiagram } from "@/lib/diagram/generator";

const CORE_MODULES = [
  "prepare_show_split",
  "issuer_sig_verify",
  "attribute_commitments",
  "selective_disclosure",
  "verifier_challenge_nonce",
  "offchain_verify",
];

const FULL_MODULES = [
  ...CORE_MODULES,
  "reblind_rerandomize",
  "nullifier_antireplay",
  "device_binding",
];

describe("Diagram Generator", () => {
  describe("High-level diagram", () => {
    it("produces a valid sequence diagram with core modules", () => {
      const result = generateDiagram(CORE_MODULES, "high_level");
      expect(result.level).toBe("high_level");
      expect(result.mermaid).toContain("sequenceDiagram");
      expect(result.mermaid).toContain("participant I as Issuer");
      expect(result.mermaid).toContain("participant W as Wallet");
      expect(result.mermaid).toContain("participant V as Verifier");
      // Should NOT have Chain actor for offchain-only
      expect(result.mermaid).not.toContain("participant C as Chain");
    });

    it("includes Chain actor when onchain_verify is present", () => {
      const result = generateDiagram([...CORE_MODULES, "onchain_verify"], "high_level");
      expect(result.mermaid).toContain("participant C as Chain");
      expect(result.mermaid).toContain("On-chain verification");
    });

    it("includes reblind step when module present", () => {
      const result = generateDiagram([...CORE_MODULES, "reblind_rerandomize"], "high_level");
      expect(result.mermaid).toContain("Reblind");
    });

    it("includes device binding step when module present", () => {
      const result = generateDiagram([...CORE_MODULES, "device_binding"], "high_level");
      expect(result.mermaid).toContain("device key");
    });

    it("includes nullifier step when module present", () => {
      const result = generateDiagram([...CORE_MODULES, "nullifier_antireplay"], "high_level");
      expect(result.mermaid).toContain("nullifier");
    });

    it("snapshot: core modules high-level", () => {
      const result = generateDiagram(CORE_MODULES, "high_level");
      expect(result.mermaid).toMatchInlineSnapshot(`
        "sequenceDiagram
            participant I as Issuer
            participant W as Wallet
            participant V as Verifier

            I->>W: Issue credential + signature
            W->>W: Create attribute commitments
            W->>W: Select attributes to disclose
            V->>W: Send challenge nonce
            W->>V: Present proof (prepare/show)
            V->>V: Verify issuer signature
            V->>V: Off-chain verification → accept/reject"
      `);
    });
  });

  describe("Crypto-level diagram", () => {
    it("produces a valid crypto-level sequence diagram", () => {
      const result = generateDiagram(CORE_MODULES, "crypto_level");
      expect(result.level).toBe("crypto_level");
      expect(result.mermaid).toContain("sequenceDiagram");
      expect(result.mermaid).toContain("Sign(isk, credential)");
      expect(result.mermaid).toContain("Commit(attributes, r)");
      expect(result.mermaid).toContain("ProveSubset");
      expect(result.mermaid).toContain("RandomNonce");
    });

    it("includes crypto-level reblind details", () => {
      const result = generateDiagram([...CORE_MODULES, "reblind_rerandomize"], "crypto_level");
      expect(result.mermaid).toContain("Reblind(C, r')");
      expect(result.mermaid).toContain("unlinkability");
    });

    it("includes device signature in crypto-level", () => {
      const result = generateDiagram([...CORE_MODULES, "device_binding"], "crypto_level");
      expect(result.mermaid).toContain("DeviceSign(dsk, ch)");
      expect(result.mermaid).toContain("sigma_ch");
    });

    it("includes nullifier PRF in crypto-level", () => {
      const result = generateDiagram([...CORE_MODULES, "nullifier_antireplay"], "crypto_level");
      expect(result.mermaid).toContain("PRF(nsk, context)");
    });

    it("snapshot: core modules crypto-level", () => {
      const result = generateDiagram(CORE_MODULES, "crypto_level");
      expect(result.mermaid).toMatchInlineSnapshot(`
        "sequenceDiagram
            participant I as Issuer
            participant W as Wallet
            participant V as Verifier

            I->>W: credential, sig_issuer = Sign(isk, credential)
            W->>W: C = Commit(attributes, r)
            W->>W: pi_selective = ProveSubset(C, disclosed_attrs)
            V->>W: ch = RandomNonce()
            W->>W: pi_prepare = Prepare(C', sig_issuer)
            W->>V: pi_show = Show(pi_prepare, ch, disclosed_attrs)
            V->>V: Verify(ipk, pi_show) = 1?
            V->>V: result = OffchainVerify(pi_show)"
      `);
    });

    it("snapshot: full modules crypto-level", () => {
      const result = generateDiagram(FULL_MODULES, "crypto_level");
      expect(result.mermaid).toMatchInlineSnapshot(`
        "sequenceDiagram
            participant I as Issuer
            participant W as Wallet
            participant V as Verifier

            W->>W: (dsk, dpk) = KeyGen()
            W->>I: Register(dpk)
            I->>W: credential, sig_issuer = Sign(isk, credential || dpk)
            W->>W: C = Commit(attributes, r)
            W->>W: C' = Reblind(C, r')
            Note over W: Fresh randomness r' ensures unlinkability
            W->>W: pi_selective = ProveSubset(C, disclosed_attrs)
            V->>W: ch = RandomNonce()
            W->>W: pi_prepare = Prepare(C', sig_issuer)
            W->>V: pi_show = Show(pi_prepare, ch, disclosed_attrs)
            W->>W: sigma_ch = DeviceSign(dsk, ch)
            W->>V: sigma_ch
            W->>W: nf = PRF(nsk, context)
            W->>V: nf
            V->>V: Verify(ipk, pi_show) = 1?
            V->>V: Verify(dpk, sigma_ch, ch) = 1?
            V->>V: Assert(nf ∉ spent_set)
            V->>V: result = OffchainVerify(pi_show)"
      `);
    });
  });

  describe("Determinism", () => {
    it("produces identical output for same input", () => {
      const a = generateDiagram(FULL_MODULES, "high_level");
      const b = generateDiagram(FULL_MODULES, "high_level");
      expect(a.mermaid).toBe(b.mermaid);
    });

    it("produces identical crypto output for same input", () => {
      const a = generateDiagram(FULL_MODULES, "crypto_level");
      const b = generateDiagram(FULL_MODULES, "crypto_level");
      expect(a.mermaid).toBe(b.mermaid);
    });
  });
});

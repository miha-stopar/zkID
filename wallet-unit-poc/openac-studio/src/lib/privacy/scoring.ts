export interface PrivacyDeduction {
  amount: number;
  reason: string;
  fix: string;
  moduleToAdd: string;
}

export interface PrivacyEarned {
  amount: number;
  reason: string;
}

export interface PrivacyMeterResult {
  score: number;
  applicablePoints: number;
  earnedPoints: number;
  deductions: PrivacyDeduction[];
  earned: PrivacyEarned[];
}

export interface PrivacyContext {
  moduleIds: Set<string>;
  unlinkabilityGoal: string;
  antiReplay: string;
  deviceBinding: string;
  presentationFrequency: string;
  verifierTopology: string;
}

interface PrivacyFactor {
  /** Weight in points when this factor is applicable */
  points: number;
  /** Returns true when this factor is relevant to the scenario */
  appliesWhen: (ctx: PrivacyContext) => boolean;
  /** The module that satisfies this factor */
  moduleId: string;
  /** Description shown when the module is present (earned) */
  earnedReason: string;
  /** Description shown when the module is missing (deduction) */
  deductionReason: (ctx: PrivacyContext) => string;
  /** Actionable fix hint shown on deductions */
  fix: string;
}

const FACTORS: PrivacyFactor[] = [
  {
    points: 15,
    appliesWhen: () => true,
    moduleId: "selective_disclosure",
    earnedReason: "Selective disclosure active — only required attributes are revealed to the verifier.",
    deductionReason: () =>
      "Selective disclosure is missing — all credential attributes are exposed to the verifier, violating data minimization.",
    fix: "Add the Selective Disclosure module.",
  },
  {
    points: 10,
    appliesWhen: () => true,
    moduleId: "attribute_commitments",
    earnedReason: "Attribute commitments active — raw attribute values are hidden behind cryptographic commitments.",
    deductionReason: () =>
      "Attribute commitments are missing — raw attribute values are sent to the verifier, no privacy-preserving proofs possible.",
    fix: "Add the Attribute Commitments module.",
  },
  {
    points: 25,
    appliesWhen: (ctx) =>
      ctx.unlinkabilityGoal !== "none" &&
      (ctx.presentationFrequency === "repeat" ||
        ctx.verifierTopology === "multi_verifier_possible_collusion"),
    moduleId: "reblind_rerandomize",
    earnedReason: "Unlinkability protected — presentations cannot be linked across sessions.",
    deductionReason: (ctx) =>
      `Unlinkability goal is '${ctx.unlinkabilityGoal}' but reblind/rerandomize is missing — presentations are linkable.`,
    fix: "Add the Reblind / Rerandomize module.",
  },
  {
    points: 10,
    appliesWhen: (ctx) =>
      ctx.verifierTopology === "multi_verifier_possible_collusion" &&
      ctx.unlinkabilityGoal === "none",
    moduleId: "reblind_rerandomize",
    earnedReason: "Verifier collusion mitigated — rerandomization prevents cross-verifier correlation.",
    deductionReason: () =>
      "Multi-verifier topology without rerandomization — colluding verifiers can correlate presentations even without an explicit unlinkability goal.",
    fix: "Add the Reblind / Rerandomize module.",
  },
  {
    points: 15,
    appliesWhen: (ctx) => ctx.antiReplay !== "none",
    moduleId: "verifier_challenge_nonce",
    earnedReason: "Anti-replay protected — verifier challenge nonce prevents proof replay.",
    deductionReason: (ctx) =>
      `Anti-replay is '${ctx.antiReplay}' but verifier challenge nonce is missing — replay attacks possible.`,
    fix: "Add the Verifier Challenge Nonce module.",
  },
  {
    points: 10,
    appliesWhen: (ctx) => ctx.antiReplay === "nullifier",
    moduleId: "nullifier_antireplay",
    earnedReason: "Nullifier active — double-use is prevented without revealing holder identity.",
    deductionReason: () =>
      "Nullifier anti-replay is configured but the nullifier module is missing — double-use is not prevented.",
    fix: "Add the Nullifier Anti-Replay module.",
  },
  {
    points: 15,
    appliesWhen: (ctx) =>
      ctx.deviceBinding === "required" && ctx.presentationFrequency === "repeat",
    moduleId: "device_binding",
    earnedReason: "Device binding active — credential possession is hardware-verified.",
    deductionReason: () =>
      "Device binding is required with repeat presentations but the module is missing — no possession proof.",
    fix: "Add the Device Binding module.",
  },
];

export function computePrivacyMeter(ctx: PrivacyContext): PrivacyMeterResult {
  const earned: PrivacyEarned[] = [];
  const deductions: PrivacyDeduction[] = [];
  let applicablePoints = 0;
  let earnedPoints = 0;

  for (const factor of FACTORS) {
    if (!factor.appliesWhen(ctx)) continue;

    applicablePoints += factor.points;

    if (ctx.moduleIds.has(factor.moduleId)) {
      earnedPoints += factor.points;
      earned.push({ amount: factor.points, reason: factor.earnedReason });
    } else {
      deductions.push({
        amount: factor.points,
        reason: factor.deductionReason(ctx),
        fix: factor.fix,
        moduleToAdd: factor.moduleId,
      });
    }
  }

  const score = applicablePoints === 0 ? 100 : Math.round((earnedPoints / applicablePoints) * 100);

  return { score, applicablePoints, earnedPoints, deductions, earned };
}

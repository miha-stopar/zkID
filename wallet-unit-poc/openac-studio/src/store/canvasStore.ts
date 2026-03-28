import { create } from "zustand";
import { MODULE_REGISTRY } from "@/lib/modules/registry";
import type { ModuleDefinition } from "@/lib/modules/types";
import { generateDiagram } from "@/lib/diagram/generator";
import type { DiagramLevel, DiagramOutput } from "@/lib/diagram/types";
import { computePrivacyMeter, type PrivacyMeterResult } from "@/lib/privacy/scoring";

export type { PrivacyDeduction, PrivacyEarned, PrivacyMeterResult } from "@/lib/privacy/scoring";

export interface WarningItem {
  severity: "warning" | "info";
  message: string;
}

interface CanvasState {
  // Active modules on the canvas
  canvasModuleIds: string[];
  // Diagram state
  diagram: DiagramOutput | null;
  diagramLevel: DiagramLevel;
  // Comparison baseline
  baselineModuleIds: string[];
  showCompare: boolean;
  // Scenario context for privacy meter
  unlinkabilityGoal: string;
  antiReplay: string;
  deviceBinding: string;
  presentationFrequency: string;
  verificationTarget: string;
  verifierTopology: string;

  // Actions
  addModule: (id: string) => void;
  removeModule: (id: string) => void;
  reorderModules: (ids: string[]) => void;
  setDiagramLevel: (level: DiagramLevel) => void;
  setShowCompare: (show: boolean) => void;
  setScenarioContext: (ctx: Partial<Pick<CanvasState, "unlinkabilityGoal" | "antiReplay" | "deviceBinding" | "presentationFrequency" | "verificationTarget" | "verifierTopology">>) => void;
  loadFromEngineOutput: (moduleIds: string[], scenario?: { unlinkabilityGoal: string; antiReplay: string; deviceBinding: string; presentationFrequency: string; verificationTarget: string; verifierTopology?: string }) => void;
  importCanvas: (json: string) => boolean;
  exportCanvas: () => string;

  // Computed
  getPrivacyMeter: () => PrivacyMeterResult;
  getWarnings: () => WarningItem[];
  getPaletteModules: () => ModuleDefinition[];
}

function regenerateDiagram(moduleIds: string[], level: DiagramLevel): DiagramOutput | null {
  if (moduleIds.length === 0) return null;
  return generateDiagram(moduleIds, level);
}

export const useCanvasStore = create<CanvasState>((set, get) => ({
  canvasModuleIds: [],
  diagram: null,
  diagramLevel: "high_level",
  baselineModuleIds: [],
  showCompare: false,
  unlinkabilityGoal: "none",
  antiReplay: "nonce_only",
  deviceBinding: "none",
  presentationFrequency: "one_time",
  verificationTarget: "offchain",
  verifierTopology: "single_verifier",

  addModule: (id) => {
    const state = get();
    if (state.canvasModuleIds.includes(id)) return;
    let newIds = [...state.canvasModuleIds, id];
    // Adding dual_verify_planB removes individual verify modules
    if (id === "dual_verify_planB") {
      newIds = newIds.filter((m) => m !== "offchain_verify" && m !== "onchain_verify");
    }
    // Adding individual verify module removes dual_verify_planB
    if (id === "offchain_verify" || id === "onchain_verify") {
      newIds = newIds.filter((m) => m !== "dual_verify_planB");
    }
    set({
      canvasModuleIds: newIds,
      diagram: regenerateDiagram(newIds, state.diagramLevel),
    });
  },

  removeModule: (id) => {
    const state = get();
    const newIds = state.canvasModuleIds.filter((m) => m !== id);
    set({
      canvasModuleIds: newIds,
      diagram: regenerateDiagram(newIds, state.diagramLevel),
    });
  },

  reorderModules: (ids) => {
    const state = get();
    set({
      canvasModuleIds: ids,
      diagram: regenerateDiagram(ids, state.diagramLevel),
    });
  },

  setDiagramLevel: (level) => {
    const state = get();
    set({
      diagramLevel: level,
      diagram: regenerateDiagram(state.canvasModuleIds, level),
    });
  },

  setShowCompare: (show) => set({ showCompare: show }),

  setScenarioContext: (ctx) => set(ctx),

  loadFromEngineOutput: (moduleIds, scenario) => {
    const state = get();
    set({
      canvasModuleIds: moduleIds,
      baselineModuleIds: moduleIds,
      diagram: regenerateDiagram(moduleIds, state.diagramLevel),
      ...(scenario ?? {}),
    });
  },

  importCanvas: (json) => {
    try {
      const parsed = JSON.parse(json);
      if (Array.isArray(parsed.canvasModuleIds)) {
        const state = get();
        set({
          canvasModuleIds: parsed.canvasModuleIds,
          diagram: regenerateDiagram(parsed.canvasModuleIds, state.diagramLevel),
          unlinkabilityGoal: parsed.unlinkabilityGoal ?? state.unlinkabilityGoal,
          antiReplay: parsed.antiReplay ?? state.antiReplay,
          deviceBinding: parsed.deviceBinding ?? state.deviceBinding,
          presentationFrequency: parsed.presentationFrequency ?? state.presentationFrequency,
          verificationTarget: parsed.verificationTarget ?? state.verificationTarget,
          verifierTopology: parsed.verifierTopology ?? state.verifierTopology,
        });
        return true;
      }
      return false;
    } catch {
      return false;
    }
  },

  exportCanvas: () => {
    const state = get();
    return JSON.stringify(
      {
        canvasModuleIds: state.canvasModuleIds,
        unlinkabilityGoal: state.unlinkabilityGoal,
        antiReplay: state.antiReplay,
        deviceBinding: state.deviceBinding,
        presentationFrequency: state.presentationFrequency,
        verificationTarget: state.verificationTarget,
        verifierTopology: state.verifierTopology,
      },
      null,
      2
    );
  },

  getPrivacyMeter: () => {
    const state = get();
    return computePrivacyMeter({
      moduleIds: new Set(state.canvasModuleIds),
      unlinkabilityGoal: state.unlinkabilityGoal,
      antiReplay: state.antiReplay,
      deviceBinding: state.deviceBinding,
      presentationFrequency: state.presentationFrequency,
      verifierTopology: state.verifierTopology,
    });
  },

  getWarnings: () => {
    const state = get();
    const ids = new Set(state.canvasModuleIds);
    const warnings: WarningItem[] = [];

    if (
      !ids.has("reblind_rerandomize") &&
      state.presentationFrequency === "repeat"
    ) {
      warnings.push({
        severity: "warning",
        message: "Linkability risk across sessions: reblind/rerandomize is missing with repeat presentations.",
      });
    }

    if (
      !ids.has("nullifier_antireplay") &&
      state.antiReplay === "nullifier"
    ) {
      warnings.push({
        severity: "warning",
        message: "Replay/double-use risk: nullifier module is missing but anti-replay requires nullifier.",
      });
    }

    if (
      state.verificationTarget === "onchain" ||
      state.verificationTarget === "both"
    ) {
      warnings.push({
        severity: "info",
        message: "On-chain verification: ensure your proving system and verifier contract meet gas and circuit constraints.",
      });
    }

    return warnings;
  },

  getPaletteModules: () => {
    const state = get();
    const ids = new Set(state.canvasModuleIds);
    return MODULE_REGISTRY.filter((m) => {
      if (ids.has(m.id)) return false;
      // When dual_verify_planB is on canvas, hide individual offchain/onchain modules
      if (ids.has("dual_verify_planB") && (m.id === "offchain_verify" || m.id === "onchain_verify")) return false;
      // When either individual verify module is on canvas, hide dual_verify_planB
      if (m.id === "dual_verify_planB" && (ids.has("offchain_verify") || ids.has("onchain_verify"))) return false;
      return true;
    });
  },
}));

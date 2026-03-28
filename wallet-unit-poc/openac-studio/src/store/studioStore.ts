import { create } from "zustand";
import type { Scenario } from "@/lib/scenario/schema";
import type { EngineOutput } from "@/lib/rules/types";
import type { DiagramOutput, DiagramLevel } from "@/lib/diagram/types";
import type { ThreatModel } from "@/lib/threats/types";
import { DEFAULT_SCENARIO } from "@/lib/scenario/defaults";
import { runEngine, getSelectedModuleIds } from "@/lib/rules/engine";
import { generateDiagram } from "@/lib/diagram/generator";
import { generateThreatModel } from "@/lib/threats/generator";

interface StudioState {
  // Inputs
  scenario: Scenario;
  step: number;
  techLevel: "basic" | "advanced";

  // Outputs
  engineOutput: EngineOutput | null;
  diagram: DiagramOutput | null;
  diagramLevel: DiagramLevel;
  threatModel: ThreatModel | null;

  // Actions
  setScenario: (scenario: Scenario) => void;
  updateField: <K extends keyof Scenario>(key: K, value: Scenario[K]) => void;
  setStep: (step: number) => void;
  setTechLevel: (level: "basic" | "advanced") => void;
  generate: () => void;
  setDiagramLevel: (level: DiagramLevel) => void;
  importScenario: (json: string) => boolean;
  exportScenario: () => string;

  // Computed helpers
  getSelectedModuleIds: () => string[];
}

export const useStudioStore = create<StudioState>((set, get) => ({
  scenario: DEFAULT_SCENARIO,
  step: 0,
  techLevel: "basic",
  engineOutput: null,
  diagram: null,
  diagramLevel: "high_level",
  threatModel: null,

  setScenario: (scenario) =>
    set({ scenario, engineOutput: null, diagram: null, threatModel: null }),

  updateField: (key, value) =>
    set((state) => ({
      scenario: { ...state.scenario, [key]: value },
      engineOutput: null,
      diagram: null,
      threatModel: null,
    })),

  setStep: (step) => set({ step }),
  setTechLevel: (level) => set({ techLevel: level }),

  generate: () => {
    const { scenario, diagramLevel } = get();
    const engineOutput = runEngine(scenario);
    const moduleIds = getSelectedModuleIds(engineOutput);
    const diagram = generateDiagram(moduleIds, diagramLevel);
    const threatModel = generateThreatModel({
      scenario,
      selectedModules: moduleIds,
    });
    set({ engineOutput, diagram, threatModel, step: 1 });
  },

  setDiagramLevel: (level) => {
    const { engineOutput } = get();
    if (engineOutput) {
      const moduleIds = getSelectedModuleIds(engineOutput);
      const diagram = generateDiagram(moduleIds, level);
      set({ diagramLevel: level, diagram });
    } else {
      set({ diagramLevel: level });
    }
  },

  importScenario: (json) => {
    try {
      const parsed = JSON.parse(json);
      if (parsed.presentationFrequency && parsed.verifierTopology) {
        set({
          scenario: parsed as Scenario,
          engineOutput: null,
          diagram: null,
          threatModel: null,
        });
        return true;
      }
      return false;
    } catch {
      return false;
    }
  },

  exportScenario: () => {
    const { scenario } = get();
    return JSON.stringify(scenario, null, 2);
  },

  getSelectedModuleIds: () => {
    const { engineOutput } = get();
    return engineOutput ? getSelectedModuleIds(engineOutput) : [];
  },
}));

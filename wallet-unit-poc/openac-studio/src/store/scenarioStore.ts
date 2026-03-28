import { create } from "zustand";
import type { Scenario } from "@/lib/scenario/schema";
import type { EngineOutput } from "@/lib/rules/types";
import type { DiagramOutput } from "@/lib/diagram/types";
import { DEFAULT_SCENARIO } from "@/lib/scenario/defaults";
import { runEngine } from "@/lib/rules/engine";
import { generateDiagram } from "@/lib/diagram/generator";
import type { DiagramLevel } from "@/lib/diagram/types";

interface ScenarioState {
  scenario: Scenario;
  engineOutput: EngineOutput | null;
  diagram: DiagramOutput | null;
  diagramLevel: DiagramLevel;

  setScenario: (scenario: Scenario) => void;
  updateField: <K extends keyof Scenario>(key: K, value: Scenario[K]) => void;
  generate: () => void;
  setDiagramLevel: (level: DiagramLevel) => void;
  importScenario: (json: string) => boolean;
  exportScenario: () => string;
}

export const useScenarioStore = create<ScenarioState>((set, get) => ({
  scenario: DEFAULT_SCENARIO,
  engineOutput: null,
  diagram: null,
  diagramLevel: "high_level",

  setScenario: (scenario) => set({ scenario, engineOutput: null, diagram: null }),

  updateField: (key, value) =>
    set((state) => ({
      scenario: { ...state.scenario, [key]: value },
      engineOutput: null,
      diagram: null,
    })),

  generate: () => {
    const { scenario, diagramLevel } = get();
    const engineOutput = runEngine(scenario);
    const moduleIds = engineOutput.modules.map((m) => m.moduleId);
    const diagram = generateDiagram(moduleIds, diagramLevel);
    set({ engineOutput, diagram });
  },

  setDiagramLevel: (level) => {
    const { engineOutput } = get();
    if (engineOutput) {
      const moduleIds = engineOutput.modules.map((m) => m.moduleId);
      const diagram = generateDiagram(moduleIds, level);
      set({ diagramLevel: level, diagram });
    } else {
      set({ diagramLevel: level });
    }
  },

  importScenario: (json) => {
    try {
      const parsed = JSON.parse(json);
      // Basic check that it looks like a scenario
      if (parsed.presentationFrequency && parsed.verifierTopology) {
        set({ scenario: parsed as Scenario, engineOutput: null, diagram: null });
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
}));

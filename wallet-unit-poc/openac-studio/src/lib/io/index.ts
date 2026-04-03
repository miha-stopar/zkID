import type { Scenario } from "../scenario/schema";
import type { EngineOutput } from "../rules/types";
import type { ThreatModel } from "../threats/types";
import { renderThreatModelMarkdown } from "../threats/markdown";

export interface ShareBlob {
  version: 1;
  scenario: Scenario;
  selectedModules: string[];
}

export function createShareBlob(
  scenario: Scenario,
  selectedModules: string[]
): string {
  const blob: ShareBlob = { version: 1, scenario, selectedModules };
  return JSON.stringify(blob, null, 2);
}

export function parseShareBlob(json: string): ShareBlob | null {
  try {
    const parsed = JSON.parse(json);
    if (
      parsed.version === 1 &&
      parsed.scenario?.presentationFrequency &&
      Array.isArray(parsed.selectedModules)
    ) {
      return parsed as ShareBlob;
    }
    return null;
  } catch {
    return null;
  }
}

export function exportModuleGraphJSON(engineOutput: EngineOutput): string {
  return JSON.stringify(engineOutput, null, 2);
}

export function exportMermaid(mermaidCode: string): string {
  return mermaidCode;
}

export function exportThreatModelMarkdown(
  model: ThreatModel,
  scenario: Scenario,
  selectedModules: string[]
): string {
  return renderThreatModelMarkdown(model, scenario, selectedModules);
}

export function exportThreatModelJSON(model: ThreatModel): string {
  return JSON.stringify(model, null, 2);
}

function downloadText(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function downloadModuleGraphJSON(engineOutput: EngineOutput) {
  downloadText("module-graph.json", exportModuleGraphJSON(engineOutput), "application/json");
}

export function downloadMermaid(mermaidCode: string) {
  downloadText("flow-diagram.mmd", mermaidCode, "text/plain");
}

export function downloadThreatModelMarkdown(
  model: ThreatModel,
  scenario: Scenario,
  selectedModules: string[]
) {
  downloadText(
    "threat-model.md",
    exportThreatModelMarkdown(model, scenario, selectedModules),
    "text/markdown"
  );
}

export function downloadThreatModelJSON(model: ThreatModel) {
  downloadText("threat-model.json", exportThreatModelJSON(model), "application/json");
}

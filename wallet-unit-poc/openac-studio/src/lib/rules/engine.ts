import type { Scenario } from "../scenario/schema";
import type { ModuleSelection } from "../modules/types";
import type { EngineOutput } from "./types";
import { RULESET } from "./ruleset";
import { getModule, MODULE_REGISTRY } from "../modules/registry";

export function runEngine(scenario: Scenario): EngineOutput {
  const selectedIds = new Set<string>();
  const explanations: string[] = [];
  const warnings: string[] = [];
  const selectionReasons = new Map<string, string>();

  // Phase 1: Evaluate all rules
  for (const rule of RULESET) {
    if (rule.predicate(scenario)) {
      const explanation = rule.explanation(scenario);

      if (rule.moduleAdds.length === 0 && explanation.startsWith("Warning:")) {
        warnings.push(explanation);
      } else {
        explanations.push(explanation);
      }

      for (const moduleId of rule.moduleAdds) {
        selectedIds.add(moduleId);
        if (!selectionReasons.has(moduleId)) {
          selectionReasons.set(moduleId, explanation);
        }
      }

      for (const moduleId of rule.moduleRemovals) {
        selectedIds.delete(moduleId);
        selectionReasons.delete(moduleId);
      }
    }
  }

  // Phase 2: Dependency resolution
  let changed = true;
  while (changed) {
    changed = false;
    for (const moduleId of [...selectedIds]) {
      const mod = getModule(moduleId);
      if (!mod) continue;
      for (const dep of mod.requires) {
        if (!selectedIds.has(dep)) {
          selectedIds.add(dep);
          const depMod = getModule(dep);
          const reason = `Auto-added: required by '${mod.title}'.`;
          selectionReasons.set(dep, reason);
          explanations.push(reason);
          changed = true;
          if (depMod) {
            // Also resolve transitive deps
          }
        }
      }
    }
  }

  // Phase 3: Conflict detection
  for (const moduleId of selectedIds) {
    const mod = getModule(moduleId);
    if (!mod) continue;
    for (const conflictId of mod.conflicts) {
      if (selectedIds.has(conflictId)) {
        // Only warn if not part of dual_verify scenario
        if (selectedIds.has("dual_verify_planB")) continue;
        const conflictMod = getModule(conflictId);
        warnings.push(
          `Conflict: '${mod.title}' conflicts with '${conflictMod?.title ?? conflictId}'. Review your module selection.`
        );
      }
    }
  }

  // Phase 4: Build output
  const modules: ModuleSelection[] = [];
  for (const moduleId of selectedIds) {
    const mod = getModule(moduleId);
    if (!mod) continue;
    modules.push({
      moduleId,
      whySelected: selectionReasons.get(moduleId) ?? "Selected by rule engine.",
      riskIfOmitted: mod.risksIfOmitted.join("; "),
    });
  }

  // Sort by registry order for deterministic output
  const registryOrder = MODULE_REGISTRY.map((m) => m.id);
  modules.sort((a, b) => registryOrder.indexOf(a.moduleId) - registryOrder.indexOf(b.moduleId));

  return { modules, explanations, warnings };
}

export function getSelectedModuleIds(output: EngineOutput): string[] {
  return output.modules.map((m) => m.moduleId);
}

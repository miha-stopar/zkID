export interface ModuleDefinition {
  id: string;
  title: string;
  description: string;
  provides: string[];
  requires: string[];
  conflicts: string[];
  risksIfOmitted: string[];
  diagramHooks: {
    actors?: string[];
    artifacts?: string[];
    sequenceSteps?: string[];
  };
}

export interface ModuleSelection {
  moduleId: string;
  whySelected: string;
  riskIfOmitted: string;
}

import type { Scenario } from "../scenario/schema";
import type { ModuleSelection } from "../modules/types";

export interface Rule {
  id: string;
  description: string;
  predicate: (scenario: Scenario) => boolean;
  moduleAdds: string[];
  moduleRemovals: string[];
  explanation: (scenario: Scenario) => string;
}

export interface EngineOutput {
  modules: ModuleSelection[];
  explanations: string[];
  warnings: string[];
}

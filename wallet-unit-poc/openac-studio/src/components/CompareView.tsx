"use client";

import { getModulesByIds } from "@/lib/modules/registry";
import type { PrivacyMeterResult, WarningItem } from "@/store/canvasStore";

interface CompareViewProps {
  baselineIds: string[];
  currentIds: string[];
  baselinePrivacy: PrivacyMeterResult;
  currentPrivacy: PrivacyMeterResult;
  baselineWarnings: WarningItem[];
  currentWarnings: WarningItem[];
}

export default function CompareView({
  baselineIds,
  currentIds,
  baselinePrivacy,
  currentPrivacy,
  baselineWarnings,
  currentWarnings,
}: CompareViewProps) {
  const baselineSet = new Set(baselineIds);
  const currentSet = new Set(currentIds);
  const added = currentIds.filter((id) => !baselineSet.has(id));
  const removed = baselineIds.filter((id) => !currentSet.has(id));

  const addedModules = getModulesByIds(added);
  const removedModules = getModulesByIds(removed);

  const scoreDiff = currentPrivacy.score - baselinePrivacy.score;

  return (
    <div className="border rounded-lg p-4 bg-white space-y-4">
      <h3 className="font-medium text-sm">Compare: Baseline vs Current</h3>

      {/* Module diff */}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <p className="text-xs font-medium text-gray-500 mb-1">Added</p>
          {addedModules.length === 0 ? (
            <p className="text-xs text-gray-400">None</p>
          ) : (
            addedModules.map((m) => (
              <div key={m.id} className="text-xs bg-emerald-50 border border-emerald-200 rounded px-2 py-1 mb-1">
                + {m.title}
              </div>
            ))
          )}
        </div>
        <div>
          <p className="text-xs font-medium text-gray-500 mb-1">Removed</p>
          {removedModules.length === 0 ? (
            <p className="text-xs text-gray-400">None</p>
          ) : (
            removedModules.map((m) => (
              <div key={m.id} className="text-xs bg-red-50 border border-red-200 rounded px-2 py-1 mb-1">
                - {m.title}
              </div>
            ))
          )}
        </div>
      </div>

      {/* Privacy score diff */}
      <div className="flex items-center gap-4 text-sm">
        <div>
          <span className="text-gray-500 text-xs">Baseline:</span>{" "}
          <span className="font-bold">{baselinePrivacy.score}</span>
        </div>
        <span className="text-gray-400">→</span>
        <div>
          <span className="text-gray-500 text-xs">Current:</span>{" "}
          <span className="font-bold">{currentPrivacy.score}</span>
        </div>
        <span
          className={`font-bold ${
            scoreDiff > 0 ? "text-emerald-600" : scoreDiff < 0 ? "text-red-600" : "text-gray-400"
          }`}
        >
          ({scoreDiff > 0 ? "+" : ""}{scoreDiff})
        </span>
      </div>

      {/* Warning diff */}
      {currentWarnings.length !== baselineWarnings.length && (
        <div className="text-xs text-gray-600">
          Warnings: {baselineWarnings.length} → {currentWarnings.length}
          {currentWarnings.length > baselineWarnings.length
            ? " (new risks introduced)"
            : " (risks mitigated)"}
        </div>
      )}
    </div>
  );
}

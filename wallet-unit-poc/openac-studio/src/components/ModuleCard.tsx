"use client";

import type { ModuleDefinition } from "@/lib/modules/types";

interface ModuleCardProps {
  module: ModuleDefinition;
  selected?: boolean;
  reason?: string;
  riskIfOmitted?: string;
  onToggle?: () => void;
  draggable?: boolean;
  compact?: boolean;
}

export default function ModuleCard({
  module,
  selected,
  reason,
  riskIfOmitted,
  onToggle,
  compact,
}: ModuleCardProps) {
  return (
    <div
      className={`border rounded-lg p-3 transition-colors ${
        selected
          ? "border-blue-400 bg-blue-50"
          : "border-gray-200 bg-white hover:border-gray-300"
      } ${onToggle ? "cursor-pointer" : ""}`}
      onClick={onToggle}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h4 className="font-medium text-sm">{module.title}</h4>
          {!compact && (
            <p className="text-xs text-gray-500 mt-0.5">{module.description}</p>
          )}
        </div>
        {selected !== undefined && (
          <span
            className={`shrink-0 w-5 h-5 rounded-full border-2 flex items-center justify-center text-xs ${
              selected
                ? "border-blue-500 bg-blue-500 text-white"
                : "border-gray-300"
            }`}
          >
            {selected ? "✓" : ""}
          </span>
        )}
      </div>

      {reason && (
        <p className="text-xs text-blue-700 mt-2 bg-blue-50 p-1.5 rounded">
          {reason}
        </p>
      )}
      {riskIfOmitted && (
        <p className="text-xs text-amber-700 mt-1 bg-amber-50 p-1.5 rounded">
          Risk if omitted: {riskIfOmitted}
        </p>
      )}
    </div>
  );
}

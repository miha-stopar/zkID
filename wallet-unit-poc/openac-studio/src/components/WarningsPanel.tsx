"use client";

import type { WarningItem } from "@/store/canvasStore";

interface WarningsPanelProps {
  warnings: WarningItem[];
}

export default function WarningsPanel({ warnings }: WarningsPanelProps) {
  if (warnings.length === 0) {
    return (
      <div className="border rounded-lg p-4 bg-white">
        <h3 className="font-medium text-sm mb-2">Stable Identifier Warnings</h3>
        <p className="text-xs text-gray-500">No warnings. Current configuration avoids known stable identifier risks.</p>
      </div>
    );
  }

  return (
    <div className="border rounded-lg p-4 bg-white">
      <h3 className="font-medium text-sm mb-3">Stable Identifier Warnings</h3>
      <div className="space-y-2">
        {warnings.map((w, i) => (
          <div
            key={i}
            className={`text-xs p-2.5 rounded border ${
              w.severity === "warning"
                ? "bg-amber-50 border-amber-200 text-amber-800"
                : "bg-blue-50 border-blue-200 text-blue-800"
            }`}
          >
            <span className="font-medium">
              {w.severity === "warning" ? "⚠ Warning" : "ℹ Note"}:
            </span>{" "}
            {w.message}
          </div>
        ))}
      </div>
    </div>
  );
}

"use client";

import { useState, useMemo } from "react";
import type { Scenario } from "@/lib/scenario/schema";
import type { ThreatModel, ThreatCategory } from "@/lib/threats/types";
import { THREAT_CATEGORY_LABELS } from "@/lib/threats/types";
import { generateThreatModel } from "@/lib/threats/generator";
import { renderThreatModelMarkdown } from "@/lib/threats/markdown";

interface ThreatModelPanelProps {
  scenario: Scenario;
  selectedModules: string[];
  compact?: boolean;
}

const SEVERITY_COLORS: Record<string, string> = {
  high: "bg-red-100 text-red-800 border-red-200",
  medium: "bg-amber-100 text-amber-800 border-amber-200",
  low: "bg-gray-100 text-gray-600 border-gray-200",
};

const SEVERITY_DOT: Record<string, string> = {
  high: "bg-red-500",
  medium: "bg-amber-500",
  low: "bg-gray-400",
};

function downloadText(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ThreatModelPanel({
  scenario,
  selectedModules,
  compact = false,
}: ThreatModelPanelProps) {
  const [expandedCategories, setExpandedCategories] = useState<Set<ThreatCategory>>(new Set());

  const model: ThreatModel = useMemo(
    () => generateThreatModel({ scenario, selectedModules }),
    [scenario, selectedModules]
  );

  const toggleCategory = (cat: ThreatCategory) => {
    setExpandedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  };

  const handleExportMarkdown = () => {
    const md = renderThreatModelMarkdown(model, scenario, selectedModules);
    downloadText("threat-model.md", md, "text/markdown");
  };

  const handleExportJSON = () => {
    const json = JSON.stringify(model, null, 2);
    downloadText("threat-model.json", json, "application/json");
  };

  const applicableCount = model.checklist.reduce(
    (sum, g) => sum + g.items.filter((i) => i.applicable).length,
    0
  );
  const totalCount = model.checklist.reduce(
    (sum, g) => sum + g.items.length,
    0
  );

  return (
    <div className="space-y-3">
      {/* Header + Export buttons */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className={compact ? "font-medium text-sm" : "font-semibold"}>
            Threat Model
          </h3>
          <p className="text-xs text-gray-500">
            {applicableCount} applicable / {totalCount} total threats
          </p>
        </div>
        <div className="flex gap-1.5">
          <button
            onClick={handleExportMarkdown}
            className="text-xs px-2.5 py-1 border rounded hover:bg-gray-50"
          >
            Export MD
          </button>
          <button
            onClick={handleExportJSON}
            className="text-xs px-2.5 py-1 border rounded hover:bg-gray-50"
          >
            Export JSON
          </button>
        </div>
      </div>

      {/* Warnings */}
      {model.warnings.length > 0 && (
        <div className="space-y-1">
          {model.warnings.map((w, i) => (
            <p
              key={i}
              className="text-xs bg-amber-50 border border-amber-200 rounded p-2 text-amber-800"
            >
              {w}
            </p>
          ))}
        </div>
      )}

      {/* Top Risks */}
      {model.summary.topRisks.length > 0 && (
        <div className="bg-white border rounded-lg p-3">
          <h4 className="text-sm font-medium mb-2">Top Risks</h4>
          <div className="space-y-1.5">
            {model.summary.topRisks.map((risk) => (
              <div
                key={risk.id}
                className="flex items-start gap-2 text-xs"
              >
                <span
                  className={`shrink-0 mt-0.5 w-2 h-2 rounded-full ${SEVERITY_DOT[risk.severity] ?? "bg-gray-400"}`}
                />
                <div>
                  <span className="font-medium">{risk.title}</span>
                  <span className="text-gray-500 ml-1">
                    [{risk.severity}]
                  </span>
                  {!compact && (
                    <p className="text-gray-500 mt-0.5">{risk.why}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Checklist by category */}
      <div className="space-y-1">
        {model.checklist.map((group) => {
          const applicableInGroup = group.items.filter((i) => i.applicable).length;
          if (applicableInGroup === 0 && compact) return null;
          const isExpanded = expandedCategories.has(group.category);

          return (
            <div key={group.category} className="border rounded-lg overflow-hidden">
              <button
                onClick={() => toggleCategory(group.category)}
                className="w-full flex items-center justify-between px-3 py-2 bg-gray-50 hover:bg-gray-100 text-left text-sm"
              >
                <span className="font-medium">
                  {THREAT_CATEGORY_LABELS[group.category]}
                </span>
                <span className="text-xs text-gray-500">
                  {applicableInGroup}/{group.items.length} applicable
                  {isExpanded ? " ▲" : " ▼"}
                </span>
              </button>

              {isExpanded && (
                <div className="divide-y">
                  {group.items.map((item) => (
                    <div
                      key={item.threatId}
                      className={`px-3 py-2 text-xs ${
                        item.applicable ? "" : "opacity-50"
                      }`}
                    >
                      <div className="flex items-start gap-2">
                        <span
                          className={`shrink-0 mt-0.5 px-1.5 py-0.5 rounded text-[10px] font-medium border ${
                            SEVERITY_COLORS[item.severity] ?? ""
                          }`}
                        >
                          {item.severity.toUpperCase()}
                        </span>
                        <div className="flex-1 min-w-0">
                          <p className="font-medium">{item.title}</p>
                          {item.applicable && (
                            <>
                              <p className="text-gray-500 mt-1">
                                {item.whyApplicable}
                              </p>
                              {/* Mitigations */}
                              {item.mitigations.length > 0 && (
                                <div className="mt-1.5 space-y-0.5">
                                  {item.mitigations.map((m) => (
                                    <div
                                      key={m.id}
                                      className="flex items-center gap-1.5"
                                    >
                                      <span
                                        className={`w-3.5 h-3.5 rounded-sm flex items-center justify-center text-[10px] ${
                                          m.satisfied
                                            ? "bg-emerald-100 text-emerald-700"
                                            : "bg-red-100 text-red-700"
                                        }`}
                                      >
                                        {m.satisfied ? "✓" : "✗"}
                                      </span>
                                      <span>{m.title}</span>
                                      <span className="text-gray-400">
                                        — {m.how}
                                      </span>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Assumptions (non-compact only) */}
      {!compact && (
        <details className="text-xs">
          <summary className="text-gray-500 cursor-pointer hover:text-gray-700">
            Assumptions & Out of Scope
          </summary>
          <div className="mt-2 space-y-2 pl-2">
            <div>
              <p className="font-medium text-gray-700 mb-1">Assumptions:</p>
              <ul className="list-disc pl-4 text-gray-500 space-y-0.5">
                {model.summary.assumptions.map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
              </ul>
            </div>
            <div>
              <p className="font-medium text-gray-700 mb-1">Out of Scope:</p>
              <ul className="list-disc pl-4 text-gray-500 space-y-0.5">
                {model.summary.outOfScope.map((o, i) => (
                  <li key={i}>{o}</li>
                ))}
              </ul>
            </div>
          </div>
        </details>
      )}
    </div>
  );
}

"use client";

import Link from "next/link";
import type { PrivacyMeterResult } from "@/lib/privacy/scoring";
import { CheckCircle2, XCircle, HelpCircle } from "lucide-react";

interface PrivacyMeterProps {
  result: PrivacyMeterResult;
  onAddModule?: (moduleId: string) => void;
}

function scoreColor(score: number): string {
  if (score >= 80) return "bg-emerald-500";
  if (score >= 50) return "bg-yellow-500";
  return "bg-red-500";
}

function scoreLabel(score: number): string {
  if (score >= 80) return "Good";
  if (score >= 50) return "Moderate";
  return "Poor";
}

export default function PrivacyMeter({ result, onAddModule }: PrivacyMeterProps) {
  return (
    <div className="border rounded-lg p-4 bg-white">
      <div className="flex items-center gap-1.5 mb-3">
        <h3 className="font-medium text-sm">Privacy Meter</h3>
        <Link href="/docs#privacy-score" className="text-gray-400 hover:text-gray-600 transition-colors">
          <HelpCircle className="h-3.5 w-3.5" />
        </Link>
      </div>

      <div className="flex items-center gap-3 mb-1">
        <div className="flex-1 h-4 bg-gray-200 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-300 ${scoreColor(result.score)}`}
            style={{ width: `${result.score}%` }}
          />
        </div>
        <span className="text-sm font-bold w-12 text-right">{result.score}%</span>
      </div>

      <div className="flex items-center justify-between mb-3">
        <p className={`text-xs font-medium ${result.score >= 80 ? "text-emerald-700" : result.score >= 50 ? "text-yellow-700" : "text-red-700"}`}>
          {scoreLabel(result.score)}
        </p>
        <p className="text-xs text-gray-400">
          {result.applicablePoints === 0
            ? "No applicable factors"
            : `${result.earnedPoints}/${result.applicablePoints} pts`}
        </p>
      </div>

      {/* Earned points */}
      {result.earned.length > 0 && (
        <div className="space-y-1.5 mb-3">
          {result.earned.map((e, i) => (
            <div key={i} className="flex items-start gap-2 text-xs bg-emerald-50 border border-emerald-200 rounded p-2">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 shrink-0 mt-0.5" />
              <div>
                <span className="font-medium text-emerald-800">+{e.amount}</span>{" "}
                <span className="text-emerald-700">{e.reason}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Deductions with fix hints */}
      {result.deductions.length > 0 && (
        <div className="space-y-1.5">
          {result.deductions.map((d, i) => (
            <div key={i} className="text-xs bg-red-50 border border-red-200 rounded p-2">
              <div className="flex items-start gap-2">
                <XCircle className="h-3.5 w-3.5 text-red-500 shrink-0 mt-0.5" />
                <div>
                  <span className="font-medium text-red-800">-{d.amount}</span>{" "}
                  <span className="text-red-700">{d.reason}</span>
                  <p className="text-red-600 mt-1">
                    {onAddModule ? (
                      <button
                        onClick={() => onAddModule(d.moduleToAdd)}
                        className="underline hover:text-red-800 transition-colors"
                      >
                        {d.fix}
                      </button>
                    ) : (
                      <span>{d.fix}</span>
                    )}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {result.deductions.length === 0 && result.earned.length === 0 && (
        <p className="text-xs text-gray-400">
          {result.applicablePoints === 0
            ? "No privacy factors apply to this configuration."
            : "No privacy deductions. Configuration looks good."}
        </p>
      )}
    </div>
  );
}

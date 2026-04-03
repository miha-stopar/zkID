"use client";

import { useMemo } from "react";
import Link from "next/link";
import { useStudioStore } from "@/store/studioStore";
import { SCENARIO_FIELD_LABELS, SCENARIO_OPTIONS } from "@/lib/scenario/schema";
import type { Scenario } from "@/lib/scenario/schema";
import { EXAMPLE_SCENARIOS } from "@/lib/scenario/defaults";
import { getModule } from "@/lib/modules/registry";
import { generateThreatModel } from "@/lib/threats/generator";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from "@/components/ui/accordion";
import { Tooltip, TooltipTrigger, TooltipContent } from "@/components/ui/tooltip";
import MermaidRenderer from "@/components/MermaidRenderer";
import { THREAT_CATEGORY_LABELS } from "@/lib/threats/types";
import {
  downloadModuleGraphJSON,
  downloadMermaid,
  downloadThreatModelMarkdown,
  createShareBlob,
} from "@/lib/io";
import { computePrivacyMeter } from "@/lib/privacy/scoring";
import {
  ArrowRight,
  ArrowLeft,
  Zap,
  Download,
  ExternalLink,
  HelpCircle,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  FileJson,
  FileText,
  ClipboardCopy,
} from "lucide-react";

const FIELD_HELP: Record<string, string> = {
  presentationFrequency:
    "Will the user present this credential once (e.g., one-time badge) or repeatedly (e.g., age check at stores)?",
  verifierTopology:
    "Is there one verifier, or multiple that might share data? Multi-verifier scenarios need stronger unlinkability.",
  unlinkabilityGoal:
    "Should different presentations be unlinkable? 'Cross-verifiers' is strongest but requires rerandomization.",
  antiReplay:
    "How to prevent proof reuse? Nonce adds freshness; nullifier prevents double-use while staying unlinkable.",
  deviceBinding:
    "Should the credential be bound to a specific device? Prevents credential sharing/cloning via hardware keys.",
  verificationTarget:
    "Where is the proof verified? On-chain adds transparency but has gas limits and proof size constraints.",
  credentialFormat:
    "The underlying credential format. SD-JWT and mDOC are common; this affects which crypto primitives are available.",
  revocationHandling:
    "How are credentials invalidated? Out-of-band contacts the issuer (privacy cost); in-proof is better but not yet standard.",
};

const BASIC_FIELDS: (keyof Omit<Scenario, "notes">)[] = [
  "presentationFrequency",
  "verifierTopology",
  "deviceBinding",
  "verificationTarget",
];

const ADVANCED_FIELDS: (keyof Omit<Scenario, "notes">)[] = [
  "presentationFrequency",
  "verifierTopology",
  "unlinkabilityGoal",
  "antiReplay",
  "deviceBinding",
  "verificationTarget",
  "credentialFormat",
  "revocationHandling",
];

const SEVERITY_BADGE: Record<string, "destructive" | "warning" | "secondary"> = {
  high: "destructive",
  medium: "warning",
  low: "secondary",
};

export default function StudioPage() {
  const {
    scenario,
    updateField,
    setScenario,
    step,
    setStep,
    techLevel,
    setTechLevel,
    generate,
    engineOutput,
    diagram,
    diagramLevel,
    setDiagramLevel,
    threatModel,
    getSelectedModuleIds,
  } = useStudioStore();

  const selectedModuleIds = getSelectedModuleIds();

  const fields = techLevel === "basic" ? BASIC_FIELDS : ADVANCED_FIELDS;

  // Recompute threat model for live use
  const liveModel = useMemo(() => {
    if (!engineOutput) return null;
    return (
      threatModel ??
      generateThreatModel({ scenario, selectedModules: selectedModuleIds })
    );
  }, [engineOutput, threatModel, scenario, selectedModuleIds]);

  const privacyResult = useMemo(() => {
    if (!engineOutput) return null;
    return computePrivacyMeter({
      moduleIds: new Set(selectedModuleIds),
      unlinkabilityGoal: scenario.unlinkabilityGoal,
      antiReplay: scenario.antiReplay,
      deviceBinding: scenario.deviceBinding,
      presentationFrequency: scenario.presentationFrequency,
      verifierTopology: scenario.verifierTopology,
    });
  }, [engineOutput, selectedModuleIds, scenario]);

  const handleGenerate = () => {
    generate();
  };

  const handleCopyShareBlob = () => {
    const blob = createShareBlob(scenario, selectedModuleIds);
    navigator.clipboard.writeText(blob).catch(() => {});
  };

  return (
    <div className="max-w-6xl mx-auto px-6 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold">Integration Studio</h1>
        <p className="text-gray-500 mt-1">
          Configure your requirements, get a recommended module design with threat analysis.
        </p>
      </div>

      {/* Step indicators */}
      <div className="flex items-center gap-2 mb-8">
        {["Requirements", "Recommended Design", "Export"].map((label, i) => (
          <button
            key={label}
            onClick={() => {
              if (i === 0 || engineOutput) setStep(i);
            }}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              step === i
                ? "bg-blue-600 text-white"
                : i <= step || (i > 0 && engineOutput)
                  ? "bg-gray-100 text-gray-700 hover:bg-gray-200 cursor-pointer"
                  : "bg-gray-50 text-gray-400 cursor-not-allowed"
            }`}
            disabled={i > 0 && !engineOutput}
          >
            <span className="w-5 h-5 rounded-full bg-white/20 flex items-center justify-center text-xs font-bold">
              {i + 1}
            </span>
            {label}
          </button>
        ))}
      </div>

      {/* Step 0: Requirements */}
      {step === 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-5">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>Scenario Requirements</CardTitle>
                    <CardDescription>
                      Describe your credential presentation scenario. We&apos;ll recommend the right modules.
                    </CardDescription>
                  </div>
                  <div className="flex gap-1 bg-gray-100 rounded-lg p-0.5">
                    <button
                      onClick={() => setTechLevel("basic")}
                      className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                        techLevel === "basic" ? "bg-white shadow-sm text-gray-900" : "text-gray-500"
                      }`}
                    >
                      Basic
                    </button>
                    <button
                      onClick={() => setTechLevel("advanced")}
                      className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                        techLevel === "advanced" ? "bg-white shadow-sm text-gray-900" : "text-gray-500"
                      }`}
                    >
                      Advanced
                    </button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {fields.map((field) => (
                  <div key={field}>
                    <div className="flex items-center gap-1.5 mb-1.5">
                      <label className="block text-sm font-medium text-gray-700">
                        {SCENARIO_FIELD_LABELS[field]}
                      </label>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <HelpCircle className="h-3.5 w-3.5 text-gray-400 cursor-help" />
                        </TooltipTrigger>
                        <TooltipContent className="max-w-xs">
                          <p>{FIELD_HELP[field]}</p>
                        </TooltipContent>
                      </Tooltip>
                    </div>
                    <select
                      value={scenario[field]}
                      onChange={(e) => updateField(field, e.target.value as never)}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm bg-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-colors"
                    >
                      {SCENARIO_OPTIONS[field].map((opt) => (
                        <option key={opt.value} value={opt.value}>
                          {opt.label}
                        </option>
                      ))}
                    </select>
                  </div>
                ))}

                {techLevel === "advanced" && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1.5">
                      Notes (optional)
                    </label>
                    <textarea
                      value={scenario.notes ?? ""}
                      onChange={(e) => updateField("notes", e.target.value)}
                      rows={2}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-colors"
                      placeholder="Any additional context..."
                    />
                  </div>
                )}

                <Button onClick={handleGenerate} className="w-full" size="lg">
                  <Zap className="mr-2 h-4 w-4" />
                  Generate Recommended Design
                </Button>
              </CardContent>
            </Card>
          </div>

          {/* Presets sidebar */}
          <div className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Quick Presets</CardTitle>
                <CardDescription>Load a common scenario to start.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                {Object.entries(EXAMPLE_SCENARIOS).map(([key, { name, scenario: s }]) => (
                  <button
                    key={key}
                    onClick={() => setScenario(s)}
                    className="w-full text-left px-3 py-2.5 rounded-lg border border-gray-200 hover:border-blue-300 hover:bg-blue-50 transition-colors text-sm"
                  >
                    <span className="font-medium">{name}</span>
                  </button>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Import</CardTitle>
              </CardHeader>
              <CardContent>
                <Button
                  variant="outline"
                  size="sm"
                  className="w-full"
                  onClick={() => {
                    const input = prompt("Paste scenario JSON:");
                    if (input) {
                      const { importScenario } = useStudioStore.getState();
                      if (!importScenario(input)) alert("Invalid scenario JSON");
                    }
                  }}
                >
                  Import Scenario JSON
                </Button>
              </CardContent>
            </Card>
          </div>
        </div>
      )}

      {/* Step 1: Recommended Design */}
      {step === 1 && engineOutput && (
        <div className="space-y-6">
          {/* Top summary bar */}
          <div className="flex flex-wrap items-center gap-4 p-4 bg-white border rounded-xl">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-gray-500">Modules:</span>
              <Badge>{engineOutput.modules.length}</Badge>
            </div>
            {privacyResult !== null && (
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-gray-500">Privacy:</span>
                <Badge variant={privacyResult.score >= 80 ? "success" : privacyResult.score >= 50 ? "warning" : "destructive"}>
                  {privacyResult.score}%
                </Badge>
                <span className="text-xs text-gray-400">
                  {privacyResult.earnedPoints}/{privacyResult.applicablePoints} pts
                </span>
              </div>
            )}
            {liveModel && (
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-gray-500">Threats:</span>
                <Badge variant="warning">
                  {liveModel.checklist.reduce((s, g) => s + g.items.filter((i) => i.applicable).length, 0)} applicable
                </Badge>
              </div>
            )}
            {engineOutput.warnings.length > 0 && (
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-500" />
                <span className="text-sm text-amber-700">{engineOutput.warnings.length} warning(s)</span>
              </div>
            )}
            <div className="ml-auto flex gap-2">
              <Button variant="ghost" size="sm" onClick={() => setStep(0)}>
                <ArrowLeft className="mr-1.5 h-3.5 w-3.5" />
                Edit Requirements
              </Button>
              <Button size="sm" onClick={() => setStep(2)}>
                Export
                <ArrowRight className="ml-1.5 h-3.5 w-3.5" />
              </Button>
            </div>
          </div>

          <Tabs defaultValue="modules" className="space-y-4">
            <TabsList>
              <TabsTrigger value="modules">Modules</TabsTrigger>
              <TabsTrigger value="diagram">Diagram</TabsTrigger>
              <TabsTrigger value="threats">Threat Analysis</TabsTrigger>
            </TabsList>

            {/* Modules tab */}
            <TabsContent value="modules">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {engineOutput.modules.map((sel) => {
                  const mod = getModule(sel.moduleId);
                  if (!mod) return null;
                  return (
                    <Card key={sel.moduleId} className="hover:shadow-md transition-shadow">
                      <CardContent className="p-4 space-y-2">
                        <div className="flex items-start justify-between">
                          <h4 className="font-semibold text-sm">{mod.title}</h4>
                          <Badge variant="default" className="shrink-0 ml-2">
                            {mod.id}
                          </Badge>
                        </div>
                        <p className="text-xs text-gray-600">{mod.description}</p>
                        <div className="pt-1 space-y-1">
                          <div className="flex items-start gap-1.5 text-xs">
                            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 mt-0.5 shrink-0" />
                            <span className="text-gray-600">{sel.whySelected}</span>
                          </div>
                          <div className="flex items-start gap-1.5 text-xs">
                            <AlertTriangle className="h-3.5 w-3.5 text-amber-500 mt-0.5 shrink-0" />
                            <span className="text-gray-500">{sel.riskIfOmitted}</span>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>

              {engineOutput.warnings.length > 0 && (
                <Card className="mt-4 border-amber-200 bg-amber-50">
                  <CardContent className="p-4 space-y-1.5">
                    <h4 className="text-sm font-medium text-amber-800">Warnings</h4>
                    {engineOutput.warnings.map((w, i) => (
                      <p key={i} className="text-xs text-amber-700">{w}</p>
                    ))}
                  </CardContent>
                </Card>
              )}

              <div className="mt-4">
                <Link href={`/explore?load=studio`}>
                  <Button variant="outline">
                    <ExternalLink className="mr-2 h-3.5 w-3.5" />
                    Open in Explore Sandbox
                  </Button>
                </Link>
              </div>
            </TabsContent>

            {/* Diagram tab */}
            <TabsContent value="diagram">
              <Card>
                <CardContent className="p-5">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold">Sequence Diagram</h3>
                    <div className="flex gap-1 bg-gray-100 rounded-lg p-0.5">
                      <button
                        onClick={() => setDiagramLevel("high_level")}
                        className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                          diagramLevel === "high_level" ? "bg-white shadow-sm text-gray-900" : "text-gray-500"
                        }`}
                      >
                        High-level
                      </button>
                      <button
                        onClick={() => setDiagramLevel("crypto_level")}
                        className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                          diagramLevel === "crypto_level" ? "bg-white shadow-sm text-gray-900" : "text-gray-500"
                        }`}
                      >
                        Crypto-level
                      </button>
                    </div>
                  </div>
                  <p className="text-xs text-gray-500 mt-2">
                    {diagramLevel === "high_level"
                      ? "Conceptual overview of actors and steps — suited for stakeholders and documentation."
                      : "Cryptographic operations with mathematical notation — suited for implementers and cryptographers."}
                  </p>
                  {diagram && <MermaidRenderer chart={diagram.mermaid} />}
                  {diagram && (
                    <details className="mt-4">
                      <summary className="text-xs text-gray-400 cursor-pointer hover:text-gray-600">
                        Raw Mermaid code
                      </summary>
                      <pre className="text-xs bg-gray-50 p-3 rounded-lg mt-2 overflow-auto max-h-40 font-mono">
                        {diagram.mermaid}
                      </pre>
                    </details>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* Threats tab */}
            <TabsContent value="threats">
              {liveModel && (
                <div className="space-y-4">
                  {/* Top risks */}
                  {liveModel.summary.topRisks.length > 0 && (
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-base">Top Risks</CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-2">
                        {liveModel.summary.topRisks.map((risk) => (
                          <div key={risk.id} className="flex items-start gap-3 text-sm">
                            <Badge variant={SEVERITY_BADGE[risk.severity]} className="shrink-0 mt-0.5">
                              {risk.severity}
                            </Badge>
                            <div>
                              <span className="font-medium">{risk.title}</span>
                              <p className="text-xs text-gray-500 mt-0.5">{risk.why}</p>
                            </div>
                          </div>
                        ))}
                      </CardContent>
                    </Card>
                  )}

                  {liveModel.warnings.length > 0 && (
                    <div className="space-y-1">
                      {liveModel.warnings.map((w, i) => (
                        <div key={i} className="flex items-center gap-2 text-xs bg-amber-50 border border-amber-200 rounded-lg p-2.5 text-amber-800">
                          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                          {w}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Checklist by category */}
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base">Threat Checklist</CardTitle>
                      <CardDescription>Grouped by category. Expand to see details and mitigation status.</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <Accordion type="multiple" className="w-full">
                        {liveModel.checklist.map((group) => {
                          const applicable = group.items.filter((i) => i.applicable).length;
                          if (applicable === 0) return null;
                          return (
                            <AccordionItem key={group.category} value={group.category}>
                              <AccordionTrigger>
                                <div className="flex items-center gap-2">
                                  <span>{THREAT_CATEGORY_LABELS[group.category]}</span>
                                  <Badge variant="secondary" className="text-[10px]">
                                    {applicable} applicable
                                  </Badge>
                                </div>
                              </AccordionTrigger>
                              <AccordionContent>
                                <div className="space-y-3">
                                  {group.items.filter((item) => item.applicable).map((item) => (
                                    <div key={item.threatId} className="bg-gray-50 rounded-lg p-3 space-y-2">
                                      <div className="flex items-start gap-2">
                                        <Badge variant={SEVERITY_BADGE[item.severity]} className="shrink-0 text-[10px]">
                                          {item.severity}
                                        </Badge>
                                        <div className="min-w-0">
                                          <p className="text-sm font-medium">{item.title}</p>
                                          <p className="text-xs text-gray-500 mt-0.5">{item.whyApplicable}</p>
                                        </div>
                                      </div>
                                      {item.mitigations.length > 0 && (
                                        <div className="pl-2 space-y-1">
                                          {item.mitigations.map((m) => (
                                            <div key={m.id} className="flex items-center gap-1.5 text-xs">
                                              {m.satisfied ? (
                                                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 shrink-0" />
                                              ) : (
                                                <XCircle className="h-3.5 w-3.5 text-red-500 shrink-0" />
                                              )}
                                              <span className={m.satisfied ? "text-gray-600" : "text-red-700"}>
                                                {m.title}
                                              </span>
                                              <span className="text-gray-400">— {m.how}</span>
                                            </div>
                                          ))}
                                        </div>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              </AccordionContent>
                            </AccordionItem>
                          );
                        })}
                      </Accordion>
                    </CardContent>
                  </Card>

                  {/* Assumptions */}
                  <details className="text-sm">
                    <summary className="text-gray-500 cursor-pointer hover:text-gray-700 font-medium">
                      Assumptions & Out of Scope
                    </summary>
                    <div className="mt-3 space-y-3 pl-1">
                      <div>
                        <p className="font-medium text-gray-700 text-xs mb-1">Assumptions:</p>
                        <ul className="text-xs text-gray-500 list-disc pl-4 space-y-0.5">
                          {liveModel.summary.assumptions.map((a, i) => <li key={i}>{a}</li>)}
                        </ul>
                      </div>
                      <div>
                        <p className="font-medium text-gray-700 text-xs mb-1">Out of Scope:</p>
                        <ul className="text-xs text-gray-500 list-disc pl-4 space-y-0.5">
                          {liveModel.summary.outOfScope.map((o, i) => <li key={i}>{o}</li>)}
                        </ul>
                      </div>
                    </div>
                  </details>
                </div>
              )}
            </TabsContent>
          </Tabs>
        </div>
      )}

      {/* Step 2: Export */}
      {step === 2 && engineOutput && (
        <div className="max-w-2xl mx-auto space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Export Artifacts</CardTitle>
              <CardDescription>Download your design outputs for implementation and review.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Button
                variant="outline"
                className="w-full justify-start"
                onClick={() => downloadModuleGraphJSON(engineOutput)}
              >
                <FileJson className="mr-3 h-4 w-4 text-blue-600" />
                Module Graph JSON
                <span className="ml-auto text-xs text-gray-400">.json</span>
              </Button>
              {diagram && (
                <Button
                  variant="outline"
                  className="w-full justify-start"
                  onClick={() => downloadMermaid(diagram.mermaid)}
                >
                  <FileText className="mr-3 h-4 w-4 text-emerald-600" />
                  Mermaid Diagram
                  <span className="ml-auto text-xs text-gray-400">.mmd</span>
                </Button>
              )}
              {liveModel && (
                <Button
                  variant="outline"
                  className="w-full justify-start"
                  onClick={() => downloadThreatModelMarkdown(liveModel, scenario, selectedModuleIds)}
                >
                  <FileText className="mr-3 h-4 w-4 text-amber-600" />
                  Threat Model Report
                  <span className="ml-auto text-xs text-gray-400">.md</span>
                </Button>
              )}
              <Button
                variant="outline"
                className="w-full justify-start"
                onClick={handleCopyShareBlob}
              >
                <ClipboardCopy className="mr-3 h-4 w-4 text-gray-500" />
                Copy Share Blob to Clipboard
                <span className="ml-auto text-xs text-gray-400">JSON</span>
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Next Steps</CardTitle>
              <CardDescription>Recommended actions before implementation.</CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="space-y-3">
                {[
                  "Confirm credential format and attribute schema with your issuer.",
                  "Decide between off-chain and on-chain verification based on latency and trust requirements.",
                  "Review the threat checklist with your security team — focus on high-severity items first.",
                  "Design your verifier challenge / nonce management approach (generation, expiry, storage).",
                  "If using nullifiers, plan the spent-set storage and lookup infrastructure.",
                  "If targeting on-chain, validate proof size fits within your chain's gas constraints.",
                ].map((text, i) => (
                  <li key={i} className="flex items-start gap-3 text-sm text-gray-700">
                    <span className="flex h-5 w-5 items-center justify-center rounded-full bg-blue-100 text-blue-700 text-xs font-bold shrink-0">
                      {i + 1}
                    </span>
                    {text}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          <div className="flex gap-3">
            <Button variant="ghost" onClick={() => setStep(1)}>
              <ArrowLeft className="mr-1.5 h-3.5 w-3.5" />
              Back to Design
            </Button>
            <Link href={`/explore?load=studio`}>
              <Button variant="outline">
                <ExternalLink className="mr-2 h-3.5 w-3.5" />
                Open in Explore Sandbox
              </Button>
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}

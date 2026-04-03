"use client";

import { useState, useEffect, useMemo, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import {
  DndContext,
  closestCenter,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
  DragOverlay,
  type DragStartEvent,
} from "@dnd-kit/core";
import {
  SortableContext,
  verticalListSortingStrategy,
  useSortable,
  arrayMove,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { useCanvasStore } from "@/store/canvasStore";
import { useStudioStore } from "@/store/studioStore";
import { getModule } from "@/lib/modules/registry";
import { generateThreatModel } from "@/lib/threats/generator";
import { THREAT_CATEGORY_LABELS } from "@/lib/threats/types";
import type { Scenario } from "@/lib/scenario/schema";
import MermaidRenderer from "@/components/MermaidRenderer";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from "@/components/ui/accordion";
import { parseShareBlob, createShareBlob } from "@/lib/io";
import Link from "next/link";
import {
  GripVertical,
  X,
  Plus,
  ClipboardCopy,
  Import,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  HelpCircle,
} from "lucide-react";

function SortableModuleItem({ id, onRemove }: { id: string; onRemove: () => void }) {
  const mod = getModule(id);
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } =
    useSortable({ id });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.4 : 1,
  };

  if (!mod) return null;

  return (
    <div
      ref={setNodeRef}
      style={style}
      className="flex items-center gap-2 border rounded-lg p-2.5 bg-blue-50 border-blue-200 group/item"
    >
      <button
        {...attributes}
        {...listeners}
        className="cursor-grab text-gray-400 hover:text-gray-600 touch-none"
      >
        <GripVertical className="h-4 w-4" />
      </button>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium truncate">{mod.title}</p>
        <p className="text-xs text-gray-500 line-clamp-1 group-hover/item:line-clamp-none">{mod.description}</p>
      </div>
      <button
        onClick={onRemove}
        className="shrink-0 text-gray-400 hover:text-red-500 transition-colors"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}

const SEVERITY_BADGE: Record<string, "destructive" | "warning" | "secondary"> = {
  high: "destructive",
  medium: "warning",
  low: "secondary",
};

export default function ExplorePage() {
  return (
    <Suspense fallback={<div className="max-w-7xl mx-auto px-6 py-8 text-gray-400 text-sm">Loading...</div>}>
      <ExploreContent />
    </Suspense>
  );
}

function ExploreContent() {
  const {
    canvasModuleIds,
    addModule,
    removeModule,
    reorderModules,
    diagram,
    diagramLevel,
    setDiagramLevel,
    getPrivacyMeter,
    getWarnings,
    getPaletteModules,
    importCanvas,
    exportCanvas,
    unlinkabilityGoal,
    antiReplay,
    deviceBinding,
    presentationFrequency,
    verificationTarget,
    verifierTopology,
    setScenarioContext,
    loadFromEngineOutput,
  } = useCanvasStore();

  const searchParams = useSearchParams();
  const [loaded, setLoaded] = useState(false);

  // Load from studio store if ?load=studio
  useEffect(() => {
    if (loaded) return;
    if (searchParams?.get("load") === "studio") {
      const studio = useStudioStore.getState();
      const moduleIds = studio.getSelectedModuleIds();
      if (moduleIds.length > 0) {
        loadFromEngineOutput(moduleIds, {
          unlinkabilityGoal: studio.scenario.unlinkabilityGoal,
          antiReplay: studio.scenario.antiReplay,
          deviceBinding: studio.scenario.deviceBinding,
          presentationFrequency: studio.scenario.presentationFrequency,
          verificationTarget: studio.scenario.verificationTarget,
          verifierTopology: studio.scenario.verifierTopology,
        });
      }
    }
    setLoaded(true);
  }, [searchParams, loaded, loadFromEngineOutput]);

  const [activeId, setActiveId] = useState<string | null>(null);
  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 5 } }));

  const privacy = getPrivacyMeter();
  const warnings = getWarnings();
  const palette = getPaletteModules();

  // Build scenario for threat model
  const canvasScenario: Scenario = useMemo(() => ({
    presentationFrequency: presentationFrequency as Scenario["presentationFrequency"],
    verifierTopology: verifierTopology as Scenario["verifierTopology"],
    unlinkabilityGoal: unlinkabilityGoal as Scenario["unlinkabilityGoal"],
    antiReplay: antiReplay as Scenario["antiReplay"],
    deviceBinding: deviceBinding as Scenario["deviceBinding"],
    verificationTarget: verificationTarget as Scenario["verificationTarget"],
    credentialFormat: "sd_jwt",
    revocationHandling: "none",
  }), [presentationFrequency, verifierTopology, unlinkabilityGoal, antiReplay, deviceBinding, verificationTarget]);

  const threatModel = useMemo(
    () => generateThreatModel({ scenario: canvasScenario, selectedModules: canvasModuleIds }),
    [canvasScenario, canvasModuleIds]
  );

  const scoreColor =
    privacy.score >= 80 ? "text-emerald-600" : privacy.score >= 50 ? "text-amber-600" : "text-red-600";
  const barColor =
    privacy.score >= 80 ? "bg-emerald-500" : privacy.score >= 50 ? "bg-amber-500" : "bg-red-500";

  const handleDragStart = (event: DragStartEvent) => setActiveId(event.active.id as string);

  const handleDragEnd = (event: DragEndEvent) => {
    setActiveId(null);
    const { active, over } = event;
    if (!over) return;
    if (!canvasModuleIds.includes(active.id as string) && over.id === "canvas-drop") {
      addModule(active.id as string);
      return;
    }
    if (active.id !== over.id && canvasModuleIds.includes(active.id as string)) {
      const oldIndex = canvasModuleIds.indexOf(active.id as string);
      const newIndex = canvasModuleIds.indexOf(over.id as string);
      if (newIndex >= 0) reorderModules(arrayMove(canvasModuleIds, oldIndex, newIndex));
    }
  };

  const handleImport = () => {
    const input = prompt("Paste share blob or canvas JSON:");
    if (!input) return;
    const blob = parseShareBlob(input);
    if (blob) {
      loadFromEngineOutput(blob.selectedModules, {
        unlinkabilityGoal: blob.scenario.unlinkabilityGoal,
        antiReplay: blob.scenario.antiReplay,
        deviceBinding: blob.scenario.deviceBinding,
        presentationFrequency: blob.scenario.presentationFrequency,
        verificationTarget: blob.scenario.verificationTarget,
        verifierTopology: blob.scenario.verifierTopology,
      });
    } else if (!importCanvas(input)) {
      alert("Invalid JSON format");
    }
  };

  const handleCopyShare = () => {
    const blob = createShareBlob(canvasScenario, canvasModuleIds);
    navigator.clipboard.writeText(blob).catch(() => {});
  };

  return (
    <div className="max-w-7xl mx-auto px-6 py-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Explore Sandbox</h1>
          <p className="text-gray-500 text-sm mt-1">
            Drag modules to build flows and see how privacy, diagrams, and threats change in real time.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={handleImport}>
            <Import className="mr-1.5 h-3.5 w-3.5" />
            Import
          </Button>
          <Button variant="outline" size="sm" onClick={handleCopyShare}>
            <ClipboardCopy className="mr-1.5 h-3.5 w-3.5" />
            Copy Share Blob
          </Button>
        </div>
      </div>

      {/* Scenario context */}
      <Card className="mb-5">
        <CardContent className="py-3 px-4 flex flex-wrap gap-3 items-center text-xs">
          <span className="font-medium text-gray-600">Context:</span>
          {[
            { label: "Frequency", value: presentationFrequency, key: "presentationFrequency", options: [["one_time","One-time"],["repeat","Repeat"]] },
            { label: "Topology", value: verifierTopology, key: "verifierTopology", options: [["single_verifier","Single"],["multi_verifier_possible_collusion","Multi-Verifier"]] },
            { label: "Unlinkability", value: unlinkabilityGoal, key: "unlinkabilityGoal", options: [["none","None"],["same_verifier_sessions","Same-Verifier"],["cross_verifiers","Cross-Verifiers"]] },
            { label: "Anti-Replay", value: antiReplay, key: "antiReplay", options: [["none","None"],["nonce_only","Nonce"],["nullifier","Nullifier"]] },
            { label: "Device", value: deviceBinding, key: "deviceBinding", options: [["none","None"],["recommended","Recommended"],["required","Required"]] },
            { label: "Target", value: verificationTarget, key: "verificationTarget", options: [["offchain","Off-chain"],["onchain","On-chain"],["both","Both"]] },
          ].map((ctrl) => (
            <label key={ctrl.key} className="flex items-center gap-1">
              <span className="text-gray-500">{ctrl.label}:</span>
              <select
                value={ctrl.value}
                onChange={(e) => setScenarioContext({ [ctrl.key]: e.target.value })}
                className="border rounded-md px-1.5 py-1 text-xs bg-white focus:ring-1 focus:ring-blue-500 outline-none"
              >
                {ctrl.options.map(([v, l]) => (
                  <option key={v} value={v}>{l}</option>
                ))}
              </select>
            </label>
          ))}
        </CardContent>
      </Card>

      <DndContext sensors={sensors} collisionDetection={closestCenter} onDragStart={handleDragStart} onDragEnd={handleDragEnd}>
        <div className="grid grid-cols-12 gap-5">
          {/* Left: Palette */}
          <div className="col-span-3 space-y-2">
            <h2 className="font-semibold text-sm text-gray-700 mb-2">Module Palette</h2>
            <div className="space-y-1.5 max-h-[70vh] overflow-y-auto pr-1">
              {palette.map((mod) => (
                <button
                  key={mod.id}
                  className="group/pal w-full text-left border rounded-lg p-2.5 bg-white hover:border-blue-300 hover:bg-blue-50/50 transition-colors"
                  onClick={() => addModule(mod.id)}
                >
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium truncate">{mod.title}</p>
                    <Plus className="h-3.5 w-3.5 text-blue-500 shrink-0" />
                  </div>
                  <p className="text-xs text-gray-500 line-clamp-2 group-hover/pal:line-clamp-none">{mod.description}</p>
                </button>
              ))}
              {palette.length === 0 && (
                <p className="text-xs text-gray-400 py-6 text-center">All modules on canvas</p>
              )}
            </div>
          </div>

          {/* Center: Canvas */}
          <div className="col-span-5">
            <h2 className="font-semibold text-sm text-gray-700 mb-2">
              Canvas
              <Badge variant="secondary" className="ml-2">{canvasModuleIds.length} modules</Badge>
            </h2>
            <div className="border-2 border-dashed border-gray-300 rounded-xl p-3 min-h-[300px] bg-gray-50/50">
              {canvasModuleIds.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <div className="h-12 w-12 rounded-full bg-gray-100 flex items-center justify-center mb-3">
                    <Plus className="h-6 w-6 text-gray-400" />
                  </div>
                  <p className="text-sm text-gray-500 font-medium">No modules yet</p>
                  <p className="text-xs text-gray-400 mt-1">Click modules from the palette to add them</p>
                </div>
              ) : (
                <SortableContext items={canvasModuleIds} strategy={verticalListSortingStrategy}>
                  <div className="space-y-1.5">
                    {canvasModuleIds.map((id) => (
                      <SortableModuleItem key={id} id={id} onRemove={() => removeModule(id)} />
                    ))}
                  </div>
                </SortableContext>
              )}
            </div>
          </div>

          {/* Right: Analysis */}
          <div className="col-span-4">
            <Tabs defaultValue="diagram">
              <TabsList className="w-full">
                <TabsTrigger value="diagram" className="flex-1">Diagram</TabsTrigger>
                <TabsTrigger value="privacy" className="flex-1">Privacy</TabsTrigger>
                <TabsTrigger value="threats" className="flex-1">Threats</TabsTrigger>
              </TabsList>

              <TabsContent value="diagram">
                {diagram ? (
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between mb-3">
                        <h3 className="font-medium text-sm">Sequence Diagram</h3>
                        <div className="flex gap-1 bg-gray-100 rounded-lg p-0.5">
                          <button
                            onClick={() => setDiagramLevel("high_level")}
                            className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
                              diagramLevel === "high_level" ? "bg-white shadow-sm text-gray-900" : "text-gray-500"
                            }`}
                          >
                            High-level
                          </button>
                          <button
                            onClick={() => setDiagramLevel("crypto_level")}
                            className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
                              diagramLevel === "crypto_level" ? "bg-white shadow-sm text-gray-900" : "text-gray-500"
                            }`}
                          >
                            Crypto
                          </button>
                        </div>
                      </div>
                      <p className="text-xs text-gray-500 mb-3">
                        {diagramLevel === "high_level"
                          ? "Conceptual overview of actors and steps — suited for stakeholders and documentation."
                          : "Cryptographic operations with mathematical notation — suited for implementers and cryptographers."}
                      </p>
                      <MermaidRenderer chart={diagram.mermaid} className="max-h-[40vh]" />
                    </CardContent>
                  </Card>
                ) : (
                  <Card>
                    <CardContent className="p-8 text-center text-sm text-gray-400">
                      Add modules to see the diagram
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              <TabsContent value="privacy">
                <Card>
                  <CardContent className="p-4 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-end gap-2">
                        <span className={`text-3xl font-bold tabular-nums ${scoreColor}`}>
                          {privacy.score}%
                        </span>
                      </div>
                      <Link href="/docs#privacy-score" className="text-gray-400 hover:text-gray-600 transition-colors" title="How is this calculated?">
                        <HelpCircle className="h-4 w-4" />
                      </Link>
                    </div>
                    <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${barColor}`}
                        style={{ width: `${privacy.score}%` }}
                      />
                    </div>
                    <p className="text-xs text-gray-500">
                      {privacy.applicablePoints === 0
                        ? "No applicable privacy factors for this configuration."
                        : `${privacy.earnedPoints} / ${privacy.applicablePoints} applicable points earned`}
                    </p>
                    {/* Earned points */}
                    {privacy.earned.length > 0 && (
                      <div className="space-y-1.5">
                        <p className="text-xs font-medium text-gray-500">Earned:</p>
                        {privacy.earned.map((e, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs">
                            <Badge variant="secondary" className="shrink-0 text-[10px] bg-emerald-100 text-emerald-800">+{e.amount}</Badge>
                            <span className="text-gray-600">{e.reason}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    {privacy.deductions.length > 0 && (
                      <div className="space-y-1.5">
                        <p className="text-xs font-medium text-gray-500">Deductions:</p>
                        {privacy.deductions.map((d, i) => (
                          <div key={i} className="text-xs space-y-1">
                            <div className="flex items-start gap-2">
                              <Badge variant="destructive" className="shrink-0 text-[10px]">-{d.amount}</Badge>
                              <span className="text-gray-600">{d.reason}</span>
                            </div>
                            <button
                              onClick={() => addModule(d.moduleToAdd)}
                              className="ml-7 text-blue-600 underline hover:text-blue-800 text-[11px]"
                            >
                              {d.fix}
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                    {warnings.length > 0 && (
                      <div className="space-y-1.5 pt-2 border-t">
                        <p className="text-xs font-medium text-gray-500">Warnings:</p>
                        {warnings.map((w, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs">
                            <AlertTriangle className={`h-3.5 w-3.5 shrink-0 mt-0.5 ${w.severity === "warning" ? "text-amber-500" : "text-blue-500"}`} />
                            <span className="text-gray-600">{w.message}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="threats">
                <Card>
                  <CardContent className="p-4 max-h-[65vh] overflow-y-auto space-y-3">
                    {/* Top risks */}
                    {threatModel.summary.topRisks.length > 0 && (
                      <div className="space-y-1.5">
                        <p className="text-xs font-medium text-gray-500">Top Risks:</p>
                        {threatModel.summary.topRisks.slice(0, 3).map((risk) => (
                          <div key={risk.id} className="flex items-start gap-2 text-xs">
                            <Badge variant={SEVERITY_BADGE[risk.severity]} className="shrink-0 text-[10px]">
                              {risk.severity}
                            </Badge>
                            <span className="font-medium">{risk.title}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    {/* Checklist */}
                    <Accordion type="multiple" className="w-full">
                      {threatModel.checklist.map((group) => {
                        const applicable = group.items.filter((i) => i.applicable).length;
                        if (applicable === 0) return null;
                        return (
                          <AccordionItem key={group.category} value={group.category}>
                            <AccordionTrigger className="text-xs py-2">
                              <div className="flex items-center gap-2">
                                <span>{THREAT_CATEGORY_LABELS[group.category]}</span>
                                <Badge variant="secondary" className="text-[10px]">{applicable}</Badge>
                              </div>
                            </AccordionTrigger>
                            <AccordionContent>
                              <div className="space-y-2">
                                {group.items.filter((item) => item.applicable).map((item) => (
                                  <div key={item.threatId} className="text-xs space-y-1">
                                    <div className="flex items-center gap-1.5">
                                      <Badge variant={SEVERITY_BADGE[item.severity]} className="text-[10px]">
                                        {item.severity}
                                      </Badge>
                                      <span className="font-medium">{item.title}</span>
                                    </div>
                                    {item.mitigations.map((m) => (
                                      <div key={m.id} className="flex items-center gap-1.5 pl-2 text-[11px]">
                                        {m.satisfied ? (
                                          <CheckCircle2 className="h-3 w-3 text-emerald-500 shrink-0" />
                                        ) : (
                                          <XCircle className="h-3 w-3 text-red-500 shrink-0" />
                                        )}
                                        <span className="text-gray-600">{m.title}</span>
                                      </div>
                                    ))}
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
              </TabsContent>
            </Tabs>
          </div>
        </div>

        <DragOverlay>
          {activeId ? (
            <div className="border rounded-lg p-2.5 bg-blue-100 border-blue-400 shadow-lg">
              <p className="text-sm font-medium">{getModule(activeId)?.title ?? activeId}</p>
            </div>
          ) : null}
        </DragOverlay>
      </DndContext>
    </div>
  );
}

"use client";

import { useEffect, useRef, useState } from "react";
import mermaid from "mermaid";

let mermaidInitialized = false;

interface MermaidRendererProps {
  chart: string;
  className?: string;
}

export default function MermaidRenderer({ chart, className }: MermaidRendererProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);
  const idRef = useRef(`mermaid-${Math.random().toString(36).slice(2)}`);

  useEffect(() => {
    if (!mermaidInitialized) {
      mermaid.initialize({
        startOnLoad: false,
        theme: "default",
        securityLevel: "loose",
        sequence: {
          diagramMarginX: 20,
          diagramMarginY: 20,
          actorMargin: 80,
          messageMargin: 40,
        },
      });
      mermaidInitialized = true;
    }
  }, []);

  useEffect(() => {
    if (!chart || !containerRef.current) return;
    setError(null);

    const render = async () => {
      try {
        const { svg } = await mermaid.render(idRef.current, chart);
        if (containerRef.current) {
          containerRef.current.innerHTML = svg;
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to render diagram");
      }
    };

    // Mermaid render uses an ID that must be unique per render call,
    // so regenerate on each chart change.
    idRef.current = `mermaid-${Math.random().toString(36).slice(2)}`;
    render();
  }, [chart]);

  if (error) {
    return (
      <div className={`border border-red-300 bg-red-50 p-4 rounded ${className ?? ""}`}>
        <p className="text-red-700 text-sm font-medium">Diagram render error</p>
        <pre className="text-red-600 text-xs mt-1 whitespace-pre-wrap">{error}</pre>
        <details className="mt-2">
          <summary className="text-xs text-red-500 cursor-pointer">Raw Mermaid</summary>
          <pre className="text-xs mt-1 bg-white p-2 rounded border overflow-auto">{chart}</pre>
        </details>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className={`overflow-auto ${className ?? ""}`}
    />
  );
}

"use client";

import { useState, useMemo } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Eye, Fingerprint, ArrowRight, Lock, Repeat, Users } from "lucide-react";

function MiniDemo() {
  const [repeat, setRepeat] = useState(false);
  const [crossVerifier, setCrossVerifier] = useState(false);

  const result = useMemo(() => {
    const modules: { name: string; important: boolean; reason: string }[] = [
      { name: "Issuer Signature", important: true, reason: "Always required for credential authenticity" },
      { name: "Attribute Commitments", important: true, reason: "Enables selective disclosure" },
      { name: "Selective Disclosure", important: true, reason: "Reveal only what's needed" },
    ];

    let score = 100;
    const deductions: string[] = [];

    if (repeat || crossVerifier) {
      modules.push({
        name: "Reblind / Rerandomize",
        important: true,
        reason: crossVerifier
          ? "Prevents colluding verifiers from linking your presentations"
          : "Prevents the same verifier from tracking repeat visits",
      });
    } else {
      score -= 15;
      deductions.push("No unlinkability protection needed (single use)");
    }

    if (crossVerifier) {
      modules.push({
        name: "Nullifier",
        important: true,
        reason: "Prevents double-use while maintaining unlinkability across verifiers",
      });
    }

    modules.push({
      name: "Verifier Nonce",
      important: true,
      reason: "Prevents replay of captured proofs",
    });

    if (!repeat && !crossVerifier) {
      score = Math.max(score, 70);
    }

    return { modules, score, deductions };
  }, [repeat, crossVerifier]);

  const scoreColor =
    result.score >= 85 ? "text-emerald-600" : result.score >= 60 ? "text-amber-600" : "text-red-600";
  const barColor =
    result.score >= 85 ? "bg-emerald-500" : result.score >= 60 ? "bg-amber-500" : "bg-red-500";

  return (
    <Card className="max-w-2xl mx-auto">
      <CardContent className="p-6 space-y-5">
        <div className="flex items-center gap-2 text-sm font-medium text-gray-700">
          <Shield className="h-4 w-4 text-blue-600" />
          Try it: toggle requirements and see what changes
        </div>

        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => setRepeat(!repeat)}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-lg border-2 text-sm font-medium transition-all ${
              repeat
                ? "border-blue-500 bg-blue-50 text-blue-700"
                : "border-gray-200 bg-white text-gray-600 hover:border-gray-300"
            }`}
          >
            <Repeat className="h-4 w-4" />
            Repeat presentations
          </button>
          <button
            onClick={() => setCrossVerifier(!crossVerifier)}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-lg border-2 text-sm font-medium transition-all ${
              crossVerifier
                ? "border-blue-500 bg-blue-50 text-blue-700"
                : "border-gray-200 bg-white text-gray-600 hover:border-gray-300"
            }`}
          >
            <Users className="h-4 w-4" />
            Cross-verifier unlinkability
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {/* Modules */}
          <div className="space-y-2">
            <p className="text-xs font-medium text-gray-500 uppercase tracking-wider">
              Required Modules
            </p>
            <div className="space-y-1.5">
              {result.modules.map((m) => (
                <div
                  key={m.name}
                  className="flex items-start gap-2 text-sm bg-gray-50 rounded-lg p-2 animate-in fade-in slide-in-from-left-2 duration-200"
                >
                  <div className="w-1.5 h-1.5 rounded-full bg-blue-500 mt-1.5 shrink-0" />
                  <div>
                    <span className="font-medium">{m.name}</span>
                    <p className="text-xs text-gray-500">{m.reason}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Privacy meter */}
          <div className="space-y-3">
            <p className="text-xs font-medium text-gray-500 uppercase tracking-wider">
              Privacy Score
            </p>
            <div className="flex items-end gap-2">
              <span className={`text-4xl font-bold tabular-nums ${scoreColor}`}>
                {result.score}
              </span>
              <span className="text-sm text-gray-400 mb-1">/ 100</span>
            </div>
            <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${barColor}`}
                style={{ width: `${result.score}%` }}
              />
            </div>
            <p className="text-xs text-gray-500">
              {repeat || crossVerifier
                ? "Strong unlinkability protection with the selected modules."
                : "Basic protection for one-time presentation scenarios."}
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function LandingPage() {
  return (
    <div className="min-h-[calc(100vh-3.5rem)]">
      {/* Hero */}
      <section className="py-20 px-6">
        <div className="max-w-3xl mx-auto text-center space-y-6">
          <Badge variant="default" className="mx-auto">
            Interactive Design Tool
          </Badge>
          <h1 className="text-4xl sm:text-5xl font-bold tracking-tight text-gray-900">
            Design anonymous credential flows
            <span className="text-blue-600"> with confidence</span>
          </h1>
          <p className="text-lg text-gray-600 max-w-2xl mx-auto leading-relaxed">
            OpenAC lets users prove things about themselves — age, membership, authorization —
            without revealing their identity. This studio helps you pick the right cryptographic
            building blocks and understand the trade-offs.
          </p>
          <div className="flex gap-3 justify-center pt-2">
            <Link href="/studio">
              <Button size="lg">
                Design my integration
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </Link>
            <Link href="/explore">
              <Button variant="outline" size="lg">
                Explore modules
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* Capability cards */}
      <section className="pb-16 px-6">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-center text-sm font-medium text-gray-500 uppercase tracking-wider mb-8">
            What OpenAC enables
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            <Card className="hover:shadow-md transition-shadow">
              <CardContent className="p-6 space-y-3">
                <div className="h-10 w-10 rounded-lg bg-blue-100 flex items-center justify-center">
                  <Eye className="h-5 w-5 text-blue-600" />
                </div>
                <h3 className="font-semibold">Unlinkable Presentations</h3>
                <p className="text-sm text-gray-600 leading-relaxed">
                  Present credentials multiple times without verifiers being able to track or
                  correlate your sessions — even if they collude. Powered by rerandomization (reblind).
                </p>
              </CardContent>
            </Card>

            <Card className="hover:shadow-md transition-shadow">
              <CardContent className="p-6 space-y-3">
                <div className="h-10 w-10 rounded-lg bg-emerald-100 flex items-center justify-center">
                  <Lock className="h-5 w-5 text-emerald-600" />
                </div>
                <h3 className="font-semibold">Minimal Disclosure</h3>
                <p className="text-sm text-gray-600 leading-relaxed">
                  Reveal only the specific attributes needed — prove you&apos;re over 18 without
                  showing your birthdate. Built on cryptographic commitments and selective disclosure.
                </p>
              </CardContent>
            </Card>

            <Card className="hover:shadow-md transition-shadow">
              <CardContent className="p-6 space-y-3">
                <div className="h-10 w-10 rounded-lg bg-amber-100 flex items-center justify-center">
                  <Fingerprint className="h-5 w-5 text-amber-600" />
                </div>
                <h3 className="font-semibold">Device Binding & Anti-Replay</h3>
                <p className="text-sm text-gray-600 leading-relaxed">
                  Prevent credential sharing with hardware-backed device keys. Stop replay attacks
                  with verifier nonces and detect double-use with nullifiers.
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Interactive demo */}
      <section className="pb-20 px-6">
        <div className="max-w-5xl mx-auto space-y-6">
          <div className="text-center space-y-2">
            <h2 className="text-2xl font-bold">See how requirements shape the design</h2>
            <p className="text-gray-600">
              Toggle requirements below and watch the module selection and privacy score update in real time.
            </p>
          </div>
          <MiniDemo />
        </div>
      </section>
    </div>
  );
}

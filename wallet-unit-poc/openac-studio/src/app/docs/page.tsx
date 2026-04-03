import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function DocsPage() {
  return (
    <div className="max-w-4xl mx-auto px-6 py-8 space-y-8">
      <div>
        <h1 className="text-2xl font-bold">Documentation</h1>
        <p className="text-gray-500 mt-1">
          How OpenAC Studio works, how to extend it, and what it does not cover.
        </p>
      </div>

      {/* How it works */}
      <Card>
        <CardHeader>
          <CardTitle>How It Works</CardTitle>
        </CardHeader>
        <CardContent className="prose prose-sm prose-gray max-w-none space-y-4">
          <p>
            OpenAC Studio is a <strong>deterministic, rule-based design tool</strong> for anonymous
            credential presentation flows. There are no LLM calls, no network requests, and no
            server-side processing — everything runs locally in your browser.
          </p>

          <h4 className="font-semibold text-gray-900 mt-4">1. Scenario Configuration</h4>
          <p>
            You describe your use case by selecting values for 8 parameters: presentation frequency,
            verifier topology, unlinkability goal, anti-replay strategy, device binding policy,
            verification target, credential format, and revocation handling.
          </p>

          <h4 className="font-semibold text-gray-900 mt-4">2. Rule Engine</h4>
          <p>
            A deterministic rule engine evaluates your scenario against a set of rules. Each rule
            checks a condition (e.g., &quot;unlinkability goal is cross-verifiers&quot;) and adds or removes
            modules accordingly. The engine then resolves module dependencies and detects conflicts.
          </p>

          <h4 className="font-semibold text-gray-900 mt-4">3. Module Graph</h4>
          <p>
            The output is an ordered list of recommended cryptographic modules. Each module includes
            an explanation of why it was selected and the risk of omitting it. Modules include:
            attribute commitments, selective disclosure, reblind/rerandomize, verifier nonce,
            nullifier, device binding, and verification targets.
          </p>

          <h4 className="font-semibold text-gray-900 mt-4">4. Diagram Generation</h4>
          <p>
            From the selected modules, a Mermaid sequence diagram is generated at two detail levels:
            a high-level overview showing actors and steps, and a crypto-level view showing actual
            cryptographic operations (commitments, signatures, proofs).
          </p>

          <h4 className="font-semibold text-gray-900 mt-4">5. Threat Model</h4>
          <p>
            A library of 22 threat templates spanning 10 security categories is evaluated against
            your scenario and selected modules. Each threat has an <code>appliesWhen</code> predicate
            and a list of mitigations with module dependencies. The generator checks whether each
            mitigation is satisfied by your current module selection.
          </p>
        </CardContent>
      </Card>

      {/* Privacy Score */}
      <Card id="privacy-score">
        <CardHeader>
          <CardTitle>Privacy Score</CardTitle>
        </CardHeader>
        <CardContent className="prose prose-sm prose-gray max-w-none space-y-4">
          <p>
            The privacy score measures what percentage of <strong>applicable</strong> privacy
            protections your configuration has in place. It is calculated as:
          </p>
          <p className="bg-gray-50 rounded-lg p-3 font-mono text-sm text-center">
            Score = (earned points / applicable points) &times; 100
          </p>
          <p>
            Not every factor applies to every scenario. For example, device binding is only
            scored when it is required and presentations are repeated. The score reflects how
            well-covered you are <em>given your specific configuration</em>, not a universal
            privacy rating.
          </p>

          <h4 className="font-semibold text-gray-900 mt-4">Scoring Factors</h4>
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b text-left">
                  <th className="py-2 pr-4 font-semibold">Factor</th>
                  <th className="py-2 pr-4 font-semibold">Points</th>
                  <th className="py-2 pr-4 font-semibold">When Applicable</th>
                  <th className="py-2 font-semibold">Module Needed</th>
                </tr>
              </thead>
              <tbody className="text-gray-600">
                <tr className="border-b">
                  <td className="py-2 pr-4 font-medium text-gray-900">Selective Disclosure</td>
                  <td className="py-2 pr-4">15</td>
                  <td className="py-2 pr-4">Always</td>
                  <td className="py-2"><code className="bg-gray-100 px-1 rounded text-xs">selective_disclosure</code></td>
                </tr>
                <tr className="border-b">
                  <td className="py-2 pr-4 font-medium text-gray-900">Attribute Commitments</td>
                  <td className="py-2 pr-4">10</td>
                  <td className="py-2 pr-4">Always</td>
                  <td className="py-2"><code className="bg-gray-100 px-1 rounded text-xs">attribute_commitments</code></td>
                </tr>
                <tr className="border-b">
                  <td className="py-2 pr-4 font-medium text-gray-900">Unlinkability</td>
                  <td className="py-2 pr-4">25</td>
                  <td className="py-2 pr-4">Unlinkability goal is set, and presentations are repeated or multi-verifier</td>
                  <td className="py-2"><code className="bg-gray-100 px-1 rounded text-xs">reblind_rerandomize</code></td>
                </tr>
                <tr className="border-b">
                  <td className="py-2 pr-4 font-medium text-gray-900">Verifier Collusion</td>
                  <td className="py-2 pr-4">10</td>
                  <td className="py-2 pr-4">Multi-verifier topology with no explicit unlinkability goal</td>
                  <td className="py-2"><code className="bg-gray-100 px-1 rounded text-xs">reblind_rerandomize</code></td>
                </tr>
                <tr className="border-b">
                  <td className="py-2 pr-4 font-medium text-gray-900">Anti-Replay</td>
                  <td className="py-2 pr-4">15</td>
                  <td className="py-2 pr-4">Any anti-replay strategy is configured</td>
                  <td className="py-2"><code className="bg-gray-100 px-1 rounded text-xs">verifier_challenge_nonce</code></td>
                </tr>
                <tr className="border-b">
                  <td className="py-2 pr-4 font-medium text-gray-900">Nullifier</td>
                  <td className="py-2 pr-4">10</td>
                  <td className="py-2 pr-4">Anti-replay strategy is &quot;nullifier&quot;</td>
                  <td className="py-2"><code className="bg-gray-100 px-1 rounded text-xs">nullifier_antireplay</code></td>
                </tr>
                <tr>
                  <td className="py-2 pr-4 font-medium text-gray-900">Device Binding</td>
                  <td className="py-2 pr-4">15</td>
                  <td className="py-2 pr-4">Device binding is required and presentations are repeated</td>
                  <td className="py-2"><code className="bg-gray-100 px-1 rounded text-xs">device_binding</code></td>
                </tr>
              </tbody>
            </table>
          </div>

          <h4 className="font-semibold text-gray-900 mt-4">Edge Cases</h4>
          <ul className="list-disc pl-4 space-y-1 text-gray-600">
            <li>
              If no factors apply (e.g., a minimal one-time, single-verifier, no-anti-replay configuration
              with all always-on modules present), the score is <strong>100</strong> — there are no
              applicable risks left to mitigate.
            </li>
            <li>
              The &quot;Unlinkability&quot; and &quot;Verifier Collusion&quot; factors are mutually
              exclusive — they cannot both be applicable at the same time, since collusion risk only
              triggers when no unlinkability goal is set.
            </li>
          </ul>
        </CardContent>
      </Card>

      {/* Key concepts */}
      <Card>
        <CardHeader>
          <CardTitle>Key Concepts</CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <h4 className="font-semibold text-sm">Unlinkability & Reblind</h4>
              <Badge>Core Privacy</Badge>
            </div>
            <p className="text-sm text-gray-600">
              When a credential is presented multiple times, verifiers can correlate presentations
              using stable proof elements. <strong>Rerandomization (reblind)</strong> generates fresh
              randomness for each presentation, making it impossible to link them — even if verifiers
              collude. This is critical for repeat presentations and multi-verifier scenarios.
            </p>
          </div>

          <div>
            <div className="flex items-center gap-2 mb-1">
              <h4 className="font-semibold text-sm">Nonce vs. Nullifier Anti-Replay</h4>
              <Badge variant="secondary">Anti-Replay</Badge>
            </div>
            <p className="text-sm text-gray-600">
              A <strong>verifier nonce</strong> is a fresh random challenge that binds the proof to a
              specific session, preventing replay of captured proofs. A <strong>nullifier</strong> is
              a deterministic value tied to the credential and context — it prevents double-use
              (like double-voting or double-spending) while maintaining unlinkability. Nonces prevent
              replay; nullifiers prevent re-use.
            </p>
          </div>

          <div>
            <div className="flex items-center gap-2 mb-1">
              <h4 className="font-semibold text-sm">Device Binding</h4>
              <Badge variant="secondary">Possession</Badge>
            </div>
            <p className="text-sm text-gray-600">
              Device binding ties the credential to a hardware-backed key (e.g., Secure Enclave, TEE).
              The wallet signs the verifier&apos;s challenge with the device key, proving physical possession.
              Without it, credentials can be exported, shared, or cloned.
            </p>
          </div>

          <div>
            <div className="flex items-center gap-2 mb-1">
              <h4 className="font-semibold text-sm">On-Chain Verification</h4>
              <Badge variant="warning">Constraints</Badge>
            </div>
            <p className="text-sm text-gray-600">
              Verifying proofs on-chain (smart contract) adds transparency and trust but introduces
              constraints: proof size must fit gas limits, the verifier contract must be audited, and
              verification key management becomes critical. This tool models on-chain as a verification
              target but does not simulate gas costs or circuit constraints.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Extending */}
      <Card>
        <CardHeader>
          <CardTitle>Extending the Tool</CardTitle>
        </CardHeader>
        <CardContent className="space-y-5 text-sm text-gray-600">
          <div>
            <h4 className="font-semibold text-gray-900 mb-1">Adding a Module</h4>
            <p className="mb-2">
              Edit <code className="bg-gray-100 px-1 rounded">src/lib/modules/registry.ts</code> and
              add a <code>ModuleDefinition</code> to the registry array. Specify its provides,
              requires, conflicts, and diagram hooks. The rule engine and diagram generator will
              automatically pick it up.
            </p>
          </div>

          <div>
            <h4 className="font-semibold text-gray-900 mb-1">Adding a Rule</h4>
            <p className="mb-2">
              Edit <code className="bg-gray-100 px-1 rounded">src/lib/rules/ruleset.ts</code> and
              add a <code>Rule</code> with a predicate function, module adds/removals, and a
              human-readable explanation. The engine resolves dependencies and conflicts automatically.
            </p>
          </div>

          <div>
            <h4 className="font-semibold text-gray-900 mb-1">Adding a Threat Template</h4>
            <p className="mb-2">
              Edit <code className="bg-gray-100 px-1 rounded">src/lib/threats/templates.ts</code> and
              add a <code>ThreatTemplate</code>. Define the <code>appliesWhen</code> predicate (receives
              scenario and selected modules), severity, mitigations with <code>dependsOnModules</code>,
              detection signals, and references. The generator handles evaluation and satisfaction checks.
            </p>
          </div>

          <div>
            <h4 className="font-semibold text-gray-900 mb-1">Threat Categories</h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-2">
              {[
                ["Soundness / Forgery", "Credential or proof forgery attacks"],
                ["Zero-Knowledge Leakage", "Unintended attribute disclosure"],
                ["Unlinkability / Linkability", "Cross-session or cross-verifier tracking"],
                ["Replay / Double-Spend", "Proof reuse or double-presentation"],
                ["Device Sharing / Cloning", "Credential export or device theft"],
                ["Issuer Tracking / Registry", "Issuer-side holder surveillance"],
                ["Verifier Collusion", "Multi-verifier correlation attacks"],
                ["Dependency / Status / Revocation", "Revocation gaps or status failures"],
                ["Implementation / Side-Channels", "Timing, memory, logging leaks"],
                ["Operational / Key Management", "Key rotation, contract audit, gas limits"],
              ].map(([name, desc]) => (
                <div key={name} className="bg-gray-50 rounded-lg p-2.5">
                  <p className="font-medium text-gray-900 text-xs">{name}</p>
                  <p className="text-xs text-gray-500">{desc}</p>
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Limitations */}
      <Card className="border-amber-200">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            Limitations
            <Badge variant="warning">Important</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-gray-600">
          <ul className="list-disc pl-4 space-y-1.5">
            <li>
              This is a <strong>checklist-based design tool</strong>, not a formal security proof
              or verification system. It identifies common risks based on configuration but does not
              guarantee completeness.
            </li>
            <li>
              The threat model covers known patterns for anonymous credential systems. Novel or
              domain-specific threats may not be included.
            </li>
            <li>
              On-chain verification constraints (gas limits, circuit compatibility, verifier contract
              correctness) are flagged as risks but not simulated.
            </li>
            <li>
              Network-level attacks, issuer misbehavior at issuance time, and physical coercion are
              out of scope.
            </li>
            <li>
              Always review the output with a qualified security team before production deployment.
            </li>
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}

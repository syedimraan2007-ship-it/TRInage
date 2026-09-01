import React, { useState } from 'react';
import { AttackPath, NormalizedFinding } from '../types';
import { Route, ShieldAlert, ChevronDown, ChevronUp, Calculator, CheckCircle2, ArrowRight, AlertTriangle } from 'lucide-react';

interface AttackPathsViewProps {
  attackPaths: AttackPath[];
  findings: NormalizedFinding[];
  onSelectAttackPath: (id: string) => void;
  onNavigateTab: (tab: string) => void;
}

export const AttackPathsView: React.FC<AttackPathsViewProps> = ({
  attackPaths,
  findings,
  onSelectAttackPath,
  onNavigateTab,
}) => {
  const [expandedPathId, setExpandedPathId] = useState<string | null>(attackPaths[0]?.id || null);

  return (
    <div className="space-y-6">
      {/* Header Description */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
            <Route className="w-5 h-5 text-cyan-400" />
            <span>Prioritized Attack Paths ({attackPaths.length})</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Deterministic contextual risk ranking based on exposure, exploitability evidence, asset criticality, and pivot complexity.
          </p>
        </div>
      </div>

      {attackPaths.length === 0 ? (
        <div className="cyber-card rounded-2xl p-12 text-center text-slate-400 border border-slate-800 space-y-3">
          <ShieldAlert className="w-12 h-12 mx-auto text-slate-600" />
          <h3 className="text-base font-bold text-slate-200">No Attack Paths Generated Yet</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Upload security scanner outputs (JSON/CSV) or load authorized sample scans in the Ingestion Hub to synthesize multi-hop vulnerability chains.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {attackPaths.map((path) => {
            const isExpanded = expandedPathId === path.id;

            return (
              <div
                key={path.id}
                className="cyber-card rounded-2xl overflow-hidden shadow-sm transition hover:border-slate-700 border border-slate-800"
              >
                {/* Header Row */}
                <div
                  className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer select-none"
                  onClick={() => setExpandedPathId(isExpanded ? null : path.id)}
                >
                  <div className="space-y-1.5 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`px-2.5 py-0.5 rounded text-[11px] font-bold uppercase font-mono tracking-wider ${
                          path.severity === 'Critical'
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : path.severity === 'High'
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : 'bg-yellow-950 text-yellow-300 border border-yellow-800'
                        }`}
                      >
                        {path.severity}
                      </span>
                      <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-950/60 px-2.5 py-0.5 rounded-lg border border-cyan-800/50">
                        Contextual Score: {path.contextualScore}/100
                      </span>
                      <span className="text-xs font-mono text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                        Confidence: <strong className="text-slate-200">{path.confidence}</strong>
                      </span>
                    </div>

                    <h3 className="text-base font-bold text-slate-100">{path.title}</h3>
                    <p className="text-xs text-slate-400 leading-relaxed max-w-4xl">{path.summary}</p>
                  </div>

                  <div className="flex items-center space-x-3 shrink-0 self-end sm:self-center">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectAttackPath(path.id);
                        onNavigateTab('attack-graph');
                      }}
                      className="px-3.5 py-1.5 bg-cyan-900/60 hover:bg-cyan-900 text-cyan-200 border border-cyan-700/50 rounded-xl text-xs font-bold flex items-center space-x-1.5 transition shadow-sm"
                    >
                      <span>Interactive Graph</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                    {isExpanded ? (
                      <ChevronUp className="w-5 h-5 text-slate-400" />
                    ) : (
                      <ChevronDown className="w-5 h-5 text-slate-400" />
                    )}
                  </div>
                </div>

                {/* Visual Node Sequence */}
                <div className="px-5 py-3 bg-slate-950/60 border-t border-slate-800/80 flex items-center space-x-2 overflow-x-auto text-xs font-mono scrollbar-none">
                  {path.nodes.map((n, i) => (
                    <React.Fragment key={n.id}>
                      <span
                        className={`px-2.5 py-1 rounded-lg whitespace-nowrap font-medium ${
                          n.isEntrypoint
                            ? 'bg-slate-800 text-slate-300 border border-slate-700'
                            : n.isTarget
                            ? 'bg-rose-950 text-rose-200 border border-rose-800'
                            : n.type === 'vulnerability'
                            ? 'bg-amber-950/80 text-amber-200 border border-amber-800/60'
                            : 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/60'
                        }`}
                      >
                        {n.label}
                      </span>
                      {i < path.nodes.length - 1 && (
                        <span className="text-slate-600 font-bold">→</span>
                      )}
                    </React.Fragment>
                  ))}
                </div>

                {/* Expanded Detailed Breakdown */}
                {isExpanded && (
                  <div className="p-5 border-t border-slate-800 bg-slate-900/40 space-y-5 text-xs">
                    {/* Deterministic Scoring Breakdown Box */}
                    <div className="bg-slate-950 border border-slate-800 rounded-2xl p-4.5 space-y-3">
                      <div className="flex items-center space-x-2 text-cyan-400 font-bold">
                        <Calculator className="w-4 h-4" />
                        <span>Deterministic Mathematical Risk Score Breakdown</span>
                      </div>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-center">
                        <div className="bg-slate-900 p-2.5 rounded-xl border border-slate-800">
                          <span className="text-[10px] text-slate-400 block">EXPOSURE</span>
                          <span className="text-sm font-bold text-slate-200">
                            {path.scoreBreakdown.exposureScore}/25
                          </span>
                        </div>
                        <div className="bg-slate-900 p-2.5 rounded-xl border border-slate-800">
                          <span className="text-[10px] text-slate-400 block">EXPLOITABILITY</span>
                          <span className="text-sm font-bold text-slate-200">
                            {path.scoreBreakdown.exploitabilityScore}/25
                          </span>
                        </div>
                        <div className="bg-slate-900 p-2.5 rounded-xl border border-slate-800">
                          <span className="text-[10px] text-slate-400 block">ASSET CRITICALITY</span>
                          <span className="text-sm font-bold text-slate-200">
                            {path.scoreBreakdown.assetCriticalityScore}/25
                          </span>
                        </div>
                        <div className="bg-slate-900 p-2.5 rounded-xl border border-slate-800">
                          <span className="text-[10px] text-slate-400 block">CHAIN IMPACT</span>
                          <span className="text-sm font-bold text-slate-200">
                            {path.scoreBreakdown.chainImpactScore}/25
                          </span>
                        </div>
                      </div>
                      <p className="text-[11px] text-slate-400 font-mono bg-slate-900 p-2.5 rounded-lg border border-slate-800/80">
                        {path.scoreBreakdown.explanation}
                      </p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Prerequisites */}
                      <div className="bg-slate-950/80 border border-slate-800 rounded-2xl p-4 space-y-2">
                        <h4 className="font-bold text-slate-200 flex items-center space-x-1.5">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                          <span>Attacker Prerequisites</span>
                        </h4>
                        <ul className="space-y-1 text-slate-400 list-disc list-inside">
                          {path.prerequisites.map((p, i) => (
                            <li key={i}>{p}</li>
                          ))}
                        </ul>
                      </div>

                      {/* Potential Impact */}
                      <div className="bg-slate-950/80 border border-slate-800 rounded-2xl p-4 space-y-2">
                        <h4 className="font-bold text-slate-200 flex items-center space-x-1.5">
                          <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                          <span>Blast Radius & Business Impact</span>
                        </h4>
                        <p className="text-slate-400 leading-relaxed">{path.impactAssessment}</p>
                      </div>
                    </div>

                    {/* Recommended Fix Sequence */}
                    <div className="bg-slate-950/80 border border-slate-800 rounded-2xl p-4 space-y-2.5">
                      <h4 className="font-bold text-slate-200 flex items-center space-x-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Recommended Remediation Sequence (Neutralize Chain)</span>
                      </h4>
                      <div className="space-y-2">
                        {path.recommendedFixSequence.map((step, idx) => (
                          <div
                            key={idx}
                            className="flex items-start space-x-2.5 text-slate-300 font-mono text-[11px] bg-slate-900/60 p-2 rounded-lg border border-slate-800/80"
                          >
                            <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 font-bold shrink-0 border border-cyan-800/60">
                              Step {idx + 1}
                            </span>
                            <span className="pt-0.5">{step}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

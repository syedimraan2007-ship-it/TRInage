import React from 'react';
import { DashboardMetrics, AttackPath, NormalizedFinding, Scan } from '../types';
import { ShieldAlert, AlertTriangle, CheckCircle2, Server, ArrowRight, Route, ShieldCheck, Activity, Terminal, UploadCloud } from 'lucide-react';

interface DashboardViewProps {
  metrics: DashboardMetrics | null;
  attackPaths: AttackPath[];
  findings: NormalizedFinding[];
  scans: Scan[];
  onNavigateTab: (tab: string) => void;
  onSelectAttackPath: (pathId: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  metrics,
  attackPaths,
  findings,
  scans,
  onNavigateTab,
  onSelectAttackPath,
}) => {
  if (!metrics) {
    return (
      <div className="p-8 text-center text-slate-400">
        <Activity className="w-8 h-8 mx-auto animate-spin text-cyan-500 mb-2" />
        <p>Loading security posture dashboard...</p>
      </div>
    );
  }

  const postureBg =
    metrics.postureRating === 'CRITICAL RISK'
      ? 'bg-rose-950/40 border-rose-800 text-rose-300'
      : metrics.postureRating === 'ELEVATED RISK'
      ? 'bg-amber-950/40 border-amber-800 text-amber-300'
      : metrics.postureRating === 'MODERATE RISK'
      ? 'bg-yellow-950/40 border-yellow-800 text-yellow-300'
      : 'bg-emerald-950/40 border-emerald-800 text-emerald-300';

  const criticalHighPaths = attackPaths.filter(p => p.severity === 'Critical' || p.severity === 'High');

  return (
    <div className="space-y-6">
      {/* Top Posture Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 relative overflow-hidden shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-3 mb-2">
              <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${postureBg}`}>
                {metrics.postureRating}
              </span>
              <span className="text-xs text-slate-400 font-mono">
                Average Contextual Path Risk: <strong className="text-slate-200">{metrics.averageContextualRisk}/100</strong>
              </span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-100">
              Defensive Threat Modeling & Attack-Path Prioritizer
            </h1>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Consolidating heterogeneous scanner findings into verified multi-stage attack paths with deterministic contextual risk scoring and bottleneck remediation intelligence.
            </p>
          </div>

          <div className="flex items-center space-x-3 shrink-0">
            <button
              onClick={() => onNavigateTab('attack-graph')}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold flex items-center space-x-2 transition shadow-sm shadow-cyan-900/30"
            >
              <Route className="w-4 h-4" />
              <span>Explore Attack Graph</span>
            </button>
            <button
              onClick={() => onNavigateTab('ingestion')}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold flex items-center space-x-2 transition"
            >
              <UploadCloud className="w-4 h-4" />
              <span>Import Scans</span>
            </button>
          </div>
        </div>
      </div>

      {/* 4 Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Findings */}
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Canonical Findings</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-slate-100">{metrics.totalFindings}</span>
            <span className="text-xs text-rose-400 font-semibold">{metrics.criticalFindings} Critical</span>
            <span className="text-xs text-amber-400 font-semibold">{metrics.highFindings} High</span>
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Deduplicated from all authorized scans</p>
        </div>

        {/* Active Attack Paths */}
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Active Attack Paths</span>
            <Route className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-slate-100">{metrics.activeAttackPaths}</span>
            <span className="text-xs text-rose-400 font-semibold">{metrics.criticalAttackPaths} Critical Chains</span>
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Multi-hop pivoting vulnerabilities</p>
        </div>

        {/* Affected Assets */}
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Exposed Assets</span>
            <Server className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-slate-100">{metrics.affectedAssets.length}</span>
            <span className="text-xs text-slate-400">Hostnames & APIs</span>
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Within authorized boundary</p>
        </div>

        {/* Remediation Progress */}
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Remediation Queue</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-slate-100">{metrics.unresolvedRemediations}</span>
            <span className="text-xs text-emerald-400 font-semibold">{metrics.resolvedRemediations} Verified Fixed</span>
          </div>
          <p className="text-[11px] text-slate-500 mt-1">High-leverage fix actions</p>
        </div>
      </div>

      {/* Main 2-Column Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Top Critical Attack Paths */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <ShieldAlert className="w-5 h-5 text-rose-400" />
              <h2 className="text-base font-bold text-slate-200">Prioritized Critical Attack Paths</h2>
            </div>
            <button
              onClick={() => onNavigateTab('attack-paths')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 font-medium"
            >
              <span>View All ({attackPaths.length})</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {criticalHighPaths.length === 0 ? (
            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-8 text-center text-slate-400">
              <ShieldCheck className="w-10 h-10 mx-auto text-emerald-400 mb-2" />
              <p className="font-medium text-slate-200">No Critical Attack Paths Detected</p>
              <p className="text-xs text-slate-500 mt-1">Import new security scans or run lab scenarios to evaluate vulnerability chaining.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {criticalHighPaths.slice(0, 4).map((path) => (
                <div
                  key={path.id}
                  className="bg-slate-900/80 hover:bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl p-4 transition cursor-pointer"
                  onClick={() => {
                    onSelectAttackPath(path.id);
                    onNavigateTab('attack-graph');
                  }}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                            path.severity === 'Critical'
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : 'bg-amber-950 text-amber-300 border border-amber-800'
                          }`}
                        >
                          {path.severity}
                        </span>
                        <span className="text-xs font-mono text-cyan-400 font-bold">
                          Risk Score: {path.contextualScore}/100
                        </span>
                        <span className="text-xs text-slate-400">• {path.nodes.length} Stages</span>
                      </div>
                      <h3 className="text-sm font-semibold text-slate-200">{path.title}</h3>
                      <p className="text-xs text-slate-400 line-clamp-2">{path.summary}</p>
                    </div>

                    <button
                      className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs shrink-0 flex items-center space-x-1"
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectAttackPath(path.id);
                        onNavigateTab('attack-graph');
                      }}
                    >
                      <span>Inspect Graph</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </div>

                  {/* Visual Node Mini-Chain */}
                  <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center space-x-1.5 overflow-x-auto text-[11px] font-mono scrollbar-none">
                    {path.nodes.map((n, i) => (
                      <React.Fragment key={n.id}>
                        <span
                          className={`px-2 py-0.5 rounded whitespace-nowrap ${
                            n.isEntrypoint
                              ? 'bg-slate-800 text-slate-300'
                              : n.isTarget
                              ? 'bg-rose-950/80 text-rose-200 border border-rose-800/60'
                              : n.type === 'vulnerability'
                              ? 'bg-amber-950/60 text-amber-200 border border-amber-800/40'
                              : 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/40'
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
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right Column: Severity Matrix & Affected Assets */}
        <div className="space-y-6">
          {/* Finding Severity Distribution */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
            <h3 className="text-sm font-bold text-slate-200 mb-3 flex items-center justify-between">
              <span>Severity Breakdown</span>
              <span className="text-xs font-mono text-slate-400">{findings.length} Total</span>
            </h3>

            <div className="space-y-2">
              {[
                { label: 'Critical', count: metrics.criticalFindings, color: 'bg-rose-500', text: 'text-rose-400' },
                { label: 'High', count: metrics.highFindings, color: 'bg-amber-500', text: 'text-amber-400' },
                { label: 'Medium', count: metrics.mediumFindings, color: 'bg-yellow-500', text: 'text-yellow-400' },
                { label: 'Low', count: metrics.lowFindings, color: 'bg-cyan-500', text: 'text-cyan-400' },
                { label: 'Info', count: metrics.infoFindings, color: 'bg-slate-500', text: 'text-slate-400' },
              ].map((item) => {
                const pct = findings.length > 0 ? (item.count / findings.length) * 100 : 0;
                return (
                  <div key={item.label} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className={`font-medium ${item.text}`}>{item.label}</span>
                      <span className="text-slate-400 font-mono">
                        {item.count} ({Math.round(pct)}%)
                      </span>
                    </div>
                    <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                      <div className={`h-full ${item.color}`} style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Exposed Assets List */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
            <h3 className="text-sm font-bold text-slate-200 mb-3 flex items-center justify-between">
              <span>Exposed Assets ({metrics.affectedAssets.length})</span>
              <button
                onClick={() => onNavigateTab('findings')}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
              >
                View Findings
              </button>
            </h3>

            <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
              {metrics.affectedAssets.map((asset) => {
                const assetFindings = findings.filter(f => f.asset === asset);
                const hasCrit = assetFindings.some(f => f.severity === 'Critical');
                const hasHigh = assetFindings.some(f => f.severity === 'High');

                return (
                  <div
                    key={asset}
                    className="flex items-center justify-between p-2 rounded bg-slate-800/50 border border-slate-800 text-xs"
                  >
                    <div className="flex items-center space-x-2 truncate">
                      <Server className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                      <span className="font-mono text-slate-200 truncate">{asset}</span>
                    </div>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-mono shrink-0 ${
                        hasCrit
                          ? 'bg-rose-950 text-rose-300'
                          : hasHigh
                          ? 'bg-amber-950 text-amber-300'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {assetFindings.length} vulns
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

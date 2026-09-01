import React from 'react';
import { DashboardMetrics, AttackPath, NormalizedFinding, Scan } from '../types';
import { ShieldAlert, AlertTriangle, CheckCircle2, Server, ArrowRight, Route, ShieldCheck, Activity, UploadCloud, Shield, TrendingDown } from 'lucide-react';

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
      <div className="p-12 text-center text-slate-400">
        <Activity className="w-8 h-8 mx-auto animate-spin text-cyan-400 mb-3" />
        <p className="font-mono text-xs">Loading defensive threat intelligence posture...</p>
      </div>
    );
  }

  const postureBg =
    metrics.postureRating === 'CRITICAL RISK'
      ? 'bg-rose-950/70 border-rose-800/80 text-rose-300'
      : metrics.postureRating === 'ELEVATED RISK'
      ? 'bg-amber-950/70 border-amber-800/80 text-amber-300'
      : metrics.postureRating === 'MODERATE RISK'
      ? 'bg-yellow-950/70 border-yellow-800/80 text-yellow-300'
      : 'bg-emerald-950/70 border-emerald-800/80 text-emerald-300';

  const criticalHighPaths = attackPaths.filter(p => p.severity === 'Critical' || p.severity === 'High');

  return (
    <div className="space-y-6">
      {/* Top Posture Banner */}
      <div className="cyber-card rounded-2xl p-6 relative overflow-hidden shadow-lg border border-slate-800">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className={`px-3 py-1 rounded-full text-[11px] font-bold font-mono tracking-wider border flex items-center space-x-1.5 ${postureBg}`}>
                <span className="w-2 h-2 rounded-full bg-current animate-pulse" />
                <span>{metrics.postureRating}</span>
              </span>
              <span className="text-xs text-slate-400 font-mono bg-slate-950/80 px-2.5 py-1 rounded-lg border border-slate-800">
                Average Contextual Path Risk: <strong className="text-cyan-400">{metrics.averageContextualRisk}/100</strong>
              </span>
              <span className="text-xs text-slate-400 font-mono bg-slate-950/80 px-2.5 py-1 rounded-lg border border-slate-800">
                Active Scans Ingested: <strong className="text-slate-200">{scans.length}</strong>
              </span>
            </div>
            <h1 className="text-xl sm:text-2xl font-extrabold text-slate-100 tracking-tight">
              Defensive Threat Modeling & Attack-Path Prioritizer
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 max-w-3xl leading-relaxed">
              Consolidating multi-scanner vulnerability findings into validated multi-hop attack paths with deterministic contextual risk scoring and high-leverage bottleneck remediation intelligence.
            </p>
          </div>

          <div className="flex items-center space-x-2.5 shrink-0 self-start lg:self-center">
            <button
              onClick={() => onNavigateTab('attack-graph')}
              className="px-4 py-2.5 bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white rounded-xl text-xs font-bold flex items-center space-x-2 transition shadow-md shadow-cyan-950"
            >
              <Route className="w-4 h-4" />
              <span>Explore Attack Graph</span>
            </button>
            <button
              onClick={() => onNavigateTab('ingestion')}
              className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl text-xs font-bold flex items-center space-x-2 transition"
            >
              <UploadCloud className="w-4 h-4 text-cyan-400" />
              <span>Import Scans</span>
            </button>
          </div>
        </div>
      </div>

      {/* 4 Primary KPI Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Findings */}
        <div className="cyber-card rounded-xl p-4.5 border border-slate-800 hover:border-cyan-500/40 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Canonical Findings</span>
            <div className="w-8 h-8 rounded-lg bg-amber-950/60 border border-amber-800/60 flex items-center justify-center text-amber-400">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-slate-100">{metrics.totalFindings}</span>
            <span className="text-xs text-rose-400 font-semibold font-mono">{metrics.criticalFindings} Critical</span>
            <span className="text-xs text-amber-400 font-semibold font-mono">{metrics.highFindings} High</span>
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Deduplicated across all scanner logs</p>
        </div>

        {/* Active Attack Paths */}
        <div className="cyber-card rounded-xl p-4.5 border border-slate-800 hover:border-rose-500/40 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Attack Paths</span>
            <div className="w-8 h-8 rounded-lg bg-rose-950/60 border border-rose-800/60 flex items-center justify-center text-rose-400">
              <Route className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-slate-100">{metrics.activeAttackPaths}</span>
            <span className="text-xs text-rose-400 font-semibold font-mono">{metrics.criticalAttackPaths} Critical Chains</span>
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Multi-stage privilege pivot sequences</p>
        </div>

        {/* Exposed Assets */}
        <div className="cyber-card rounded-xl p-4.5 border border-slate-800 hover:border-cyan-500/40 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Exposed Boundary Assets</span>
            <div className="w-8 h-8 rounded-lg bg-cyan-950/60 border border-cyan-800/60 flex items-center justify-center text-cyan-400">
              <Server className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-slate-100">{metrics.affectedAssets.length}</span>
            <span className="text-xs text-slate-400">Endpoints & Services</span>
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Within authorized testing boundary</p>
        </div>

        {/* Remediation Progress */}
        <div className="cyber-card rounded-xl p-4.5 border border-slate-800 hover:border-emerald-500/40 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Remediation Queue</span>
            <div className="w-8 h-8 rounded-lg bg-emerald-950/60 border border-emerald-800/60 flex items-center justify-center text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-slate-100">{metrics.unresolvedRemediations}</span>
            <span className="text-xs text-emerald-400 font-semibold font-mono">{metrics.resolvedRemediations} Verified Fixed</span>
          </div>
          <p className="text-[11px] text-slate-500 mt-1">High-leverage bottleneck actions</p>
        </div>
      </div>

      {/* Main 2-Column Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Prioritized Attack Paths */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <ShieldAlert className="w-5 h-5 text-rose-400" />
              <h2 className="text-base font-bold text-slate-100">Prioritized Critical Attack Paths</h2>
            </div>
            <button
              onClick={() => onNavigateTab('attack-paths')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 font-semibold transition"
            >
              <span>View All ({attackPaths.length})</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {criticalHighPaths.length === 0 ? (
            <div className="cyber-card rounded-xl p-10 text-center text-slate-400 border border-slate-800 space-y-3">
              <ShieldCheck className="w-10 h-10 mx-auto text-emerald-400" />
              <p className="font-semibold text-slate-200">No Critical Attack Paths Detected</p>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                Upload new vulnerability scans or load the pre-packaged demo scenario from the Ingestion Hub to analyze attack chains.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {criticalHighPaths.slice(0, 4).map((path) => (
                <div
                  key={path.id}
                  className="cyber-card rounded-xl p-4.5 border border-slate-800 hover:border-slate-700 transition cursor-pointer group"
                  onClick={() => {
                    onSelectAttackPath(path.id);
                    onNavigateTab('attack-graph');
                  }}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1.5 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase tracking-wider ${
                            path.severity === 'Critical'
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : 'bg-amber-950 text-amber-300 border border-amber-800'
                          }`}
                        >
                          {path.severity}
                        </span>
                        <span className="text-xs font-mono text-cyan-400 font-bold bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/60">
                          Risk: {path.contextualScore}/100
                        </span>
                        <span className="text-xs text-slate-400 font-mono">
                          {path.nodes.length} Stages
                        </span>
                      </div>
                      <h3 className="text-sm font-bold text-slate-100 group-hover:text-cyan-300 transition">
                        {path.title}
                      </h3>
                      <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                        {path.summary}
                      </p>
                    </div>

                    <button
                      className="px-3 py-1.5 bg-slate-800/90 hover:bg-slate-700 text-cyan-300 border border-slate-700 rounded-lg text-xs font-semibold shrink-0 flex items-center space-x-1.5 transition"
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
                              ? 'bg-slate-800 text-slate-300 border border-slate-700'
                              : n.isTarget
                              ? 'bg-rose-950 text-rose-200 border border-rose-800/80'
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
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right Column: Severity Matrix & Affected Assets */}
        <div className="space-y-6">
          {/* Finding Severity Distribution */}
          <div className="cyber-card rounded-xl p-5 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100">Severity Breakdown</h3>
              <span className="text-xs font-mono text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                {findings.length} Canonical
              </span>
            </div>

            <div className="space-y-2.5">
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
                      <span className={`font-semibold ${item.text}`}>{item.label}</span>
                      <span className="text-slate-400 font-mono text-[11px]">
                        {item.count} ({Math.round(pct)}%)
                      </span>
                    </div>
                    <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden border border-slate-800/60">
                      <div className={`h-full ${item.color} rounded-full transition-all duration-300`} style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Exposed Assets List */}
          <div className="cyber-card rounded-xl p-5 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100">
                Exposed Assets ({metrics.affectedAssets.length})
              </h3>
              <button
                onClick={() => onNavigateTab('findings')}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold"
              >
                View Findings
              </button>
            </div>

            <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
              {metrics.affectedAssets.map((asset) => {
                const assetFindings = findings.filter(f => f.asset === asset);
                const hasCrit = assetFindings.some(f => f.severity === 'Critical');
                const hasHigh = assetFindings.some(f => f.severity === 'High');

                return (
                  <div
                    key={asset}
                    className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs"
                  >
                    <div className="flex items-center space-x-2 truncate">
                      <Server className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      <span className="font-mono text-slate-200 truncate">{asset}</span>
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold shrink-0 ${
                        hasCrit
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : hasHigh
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-slate-800 text-slate-300 border border-slate-700'
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

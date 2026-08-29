import React, { useState } from 'react';
import { Scan, ScanComparison } from '../types';
import { GitCompare, ShieldCheck, AlertTriangle, ArrowRight, Sparkles, CheckCircle2, TrendingDown, RefreshCw } from 'lucide-react';

interface ScanComparisonViewProps {
  scans: Scan[];
  comparisons: ScanComparison[];
  onCompareScans: (scan1Id: string, scan2Id: string) => Promise<ScanComparison>;
}

export const ScanComparisonView: React.FC<ScanComparisonViewProps> = ({
  scans,
  comparisons,
  onCompareScans,
}) => {
  const [scan1Id, setScan1Id] = useState<string>(scans[0]?.id || '');
  const [scan2Id, setScan2Id] = useState<string>(scans[1]?.id || '');
  const [isComparing, setIsComparing] = useState(false);
  const [activeComparison, setActiveComparison] = useState<ScanComparison | null>(comparisons[0] || null);

  const handleRunComparison = async () => {
    if (!scan1Id || !scan2Id || scan1Id === scan2Id) return;
    setIsComparing(true);
    try {
      const comp = await onCompareScans(scan1Id, scan2Id);
      setActiveComparison(comp);
    } catch {
    } finally {
      setIsComparing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
            <GitCompare className="w-5 h-5 text-cyan-400" />
            <span>Scan Comparison & Remediation Verification</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Compare baseline vulnerability scans against post-fix scans to verify attack path elimination and track risk delta.
          </p>
        </div>
      </div>

      {/* Scan Selector Control Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <h3 className="text-sm font-bold text-slate-200">Select Scans for Delta Verification</h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
          {/* Scan 1 Baseline */}
          <div className="space-y-1">
            <label className="text-xs font-mono text-slate-400">Baseline Scan (Before Fixes):</label>
            <select
              id="baseline-scan-select"
              value={scan1Id}
              onChange={(e) => setScan1Id(e.target.value)}
              className="w-full bg-slate-800 text-xs text-slate-200 border border-slate-700 rounded-lg p-2.5"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.filename} ({new Date(s.uploadedAt).toLocaleDateString()}) - {s.deduplicatedCount} vulns
                </option>
              ))}
            </select>
          </div>

          {/* Scan 2 Comparison */}
          <div className="space-y-1">
            <label className="text-xs font-mono text-slate-400">Post-Fix Scan (After Fixes):</label>
            <select
              id="comparison-scan-select"
              value={scan2Id}
              onChange={(e) => setScan2Id(e.target.value)}
              className="w-full bg-slate-800 text-xs text-slate-200 border border-slate-700 rounded-lg p-2.5"
            >
              <option value="">-- Select Post-Fix Scan --</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id} disabled={s.id === scan1Id}>
                  {s.filename} ({new Date(s.uploadedAt).toLocaleDateString()}) - {s.deduplicatedCount} vulns
                </option>
              ))}
            </select>
          </div>

          {/* Trigger Button */}
          <div className="md:pt-5">
            <button
              id="run-compare-btn"
              onClick={handleRunComparison}
              disabled={isComparing || !scan1Id || !scan2Id || scan1Id === scan2Id}
              className="w-full py-2.5 px-4 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-500 text-white rounded-lg text-xs font-bold flex items-center justify-center space-x-2 transition shadow-sm"
            >
              {isComparing ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Computing Delta...</span>
                </>
              ) : (
                <>
                  <GitCompare className="w-4 h-4" />
                  <span>Compare & Verify Remediation</span>
                </>
              )}
            </button>
          </div>
        </div>

        {scans.length < 2 && (
          <p className="text-xs text-amber-400/90 font-mono bg-amber-950/40 p-2.5 rounded-lg border border-amber-800/40">
            Tip: Upload a second scan or load the pre-packaged "Payments Core V2 (Post-Remediation)" sample from the Ingestion Hub to run automated comparison.
          </p>
        )}
      </div>

      {/* Comparison Results */}
      {activeComparison ? (
        <div className="space-y-6">
          {/* Executive Delta Card */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <span className="px-2.5 py-0.5 rounded text-xs font-bold font-mono bg-emerald-950 text-emerald-300 border border-emerald-800 uppercase">
                  Verified Posture Delta
                </span>
                <h3 className="text-lg font-bold text-slate-100 mt-1">
                  Remediation Verification & Path Elimination Report
                </h3>
              </div>

              {/* Risk Delta Badge */}
              <div className="flex items-center space-x-3 bg-slate-950 p-3 rounded-xl border border-slate-800">
                <TrendingDown className="w-6 h-6 text-emerald-400" />
                <div>
                  <span className="text-[10px] text-slate-400 font-mono block">RESIDUAL RISK DELTA</span>
                  <span className="text-lg font-bold font-mono text-emerald-400">
                    {activeComparison.riskDelta.beforeScore} → {activeComparison.riskDelta.afterScore} pts ({activeComparison.riskDelta.scoreReductionPct}% Drop)
                  </span>
                </div>
              </div>
            </div>

            {/* AI Summary Statement */}
            <div className="bg-slate-950 border border-cyan-950 rounded-xl p-4 space-y-1.5">
              <div className="flex items-center space-x-1.5 text-xs text-cyan-400 font-bold">
                <Sparkles className="w-4 h-4" />
                <span>AI Verification Assessment</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                {activeComparison.aiSummary}
              </p>
            </div>

            {/* 4 Delta Metric Chips */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center text-xs font-mono">
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block text-[10px]">RESOLVED FINDINGS</span>
                <span className="text-lg font-bold text-emerald-400">
                  {activeComparison.resolvedFindingIds.length} Fixed
                </span>
              </div>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block text-[10px]">ELIMINATED ATTACK PATHS</span>
                <span className="text-lg font-bold text-emerald-400">
                  {activeComparison.eliminatedPathIds.length} Broken
                </span>
              </div>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block text-[10px]">PERSISTENT VULNS</span>
                <span className="text-lg font-bold text-amber-400">
                  {activeComparison.persistentFindingIds.length} Open
                </span>
              </div>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block text-[10px]">NEW / REGRESSIONS</span>
                <span className="text-lg font-bold text-rose-400">
                  {activeComparison.newFindingIds.length} New
                </span>
              </div>
            </div>
          </div>

          {/* Eliminated Attack Paths & Resolved Findings Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Eliminated Attack Paths */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-3">
              <h4 className="font-bold text-slate-200 text-xs uppercase tracking-wider flex items-center space-x-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>Eliminated Multi-Stage Attack Paths ({activeComparison.eliminatedPathIds.length})</span>
              </h4>

              {activeComparison.eliminatedPathIds.length === 0 ? (
                <p className="text-xs text-slate-500">No attack paths were completely eliminated.</p>
              ) : (
                <div className="space-y-2">
                  {activeComparison.eliminatedPathIds.map((pId) => (
                    <div
                      key={pId}
                      className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-900/50 text-xs font-mono text-emerald-300"
                    >
                      <span className="font-bold">Path Neutralized:</span> {pId}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Resolved Findings */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-3">
              <h4 className="font-bold text-slate-200 text-xs uppercase tracking-wider flex items-center space-x-1.5">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>Resolved Vulnerabilities ({activeComparison.resolvedFindingIds.length})</span>
              </h4>

              <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                {activeComparison.resolvedFindingIds.map((fId) => (
                  <div
                    key={fId}
                    className="p-2 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 flex items-center justify-between"
                  >
                    <span>{fId}</span>
                    <span className="text-[10px] text-emerald-400 font-bold uppercase">Verified Closed</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-12 text-center text-slate-400">
          <GitCompare className="w-12 h-12 mx-auto text-slate-600 mb-3" />
          <h3 className="text-base font-semibold text-slate-200">No Active Comparison Selected</h3>
          <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
            Choose a baseline scan and a follow-up post-fix scan above to generate an automated remediation verification diff.
          </p>
        </div>
      )}
    </div>
  );
};

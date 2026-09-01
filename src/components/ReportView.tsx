import React, { useState, useEffect } from 'react';
import { AssessmentReport } from '../types';
import { api } from '../api';
import { FileText, Printer, Download, ShieldCheck, RefreshCw } from 'lucide-react';

interface ReportViewProps {
  projectId: string;
}

export const ReportView: React.FC<ReportViewProps> = ({ projectId }) => {
  const [report, setReport] = useState<AssessmentReport | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    setIsLoading(true);

    api.getReport(projectId)
      .then(data => {
        if (!mounted) return;
        setReport(data);
      })
      .catch((err) => {
        console.error('Failed to generate report:', err);
      })
      .finally(() => {
        if (mounted) setIsLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, [projectId]);

  const handlePrint = () => {
    window.print();
  };

  const handleExportJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const name = report.project?.name || 'security-scope';
    a.download = `security-report-${name.toLowerCase().replace(/\s+/g, '-')}-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isLoading) {
    return (
      <div className="p-12 text-center text-slate-400">
        <RefreshCw className="w-8 h-8 mx-auto animate-spin text-cyan-400 mb-3" />
        <p className="font-mono text-xs">Compiling executive & technical security assessment report...</p>
      </div>
    );
  }

  if (!report || !report.project) {
    return (
      <div className="p-8 text-center text-slate-400 space-y-3">
        <ShieldCheck className="w-8 h-8 mx-auto text-cyan-400" />
        <p className="text-sm font-semibold text-slate-200">Generating report for active project...</p>
        <p className="text-xs text-slate-500">Ingest a scan or load a sample scan to view full executive security findings.</p>
      </div>
    );
  }

  const { project, metrics, topAttackPaths = [], prioritizedRemediations = [], highRiskAssets = [] } = report;

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Top Action Bar (hidden when printing) */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 print:hidden cyber-card p-4 rounded-2xl border border-slate-800 shadow-sm">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <span>Executive & Technical Security Posture Report</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Compiled on {new Date(report.generatedAt || Date.now()).toLocaleString()}
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            id="print-report-btn"
            onClick={handlePrint}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl text-xs font-bold flex items-center space-x-1.5 transition"
          >
            <Printer className="w-4 h-4 text-cyan-400" />
            <span>Print Report</span>
          </button>
          <button
            id="export-json-btn"
            onClick={handleExportJson}
            className="px-4 py-2 bg-cyan-900/80 hover:bg-cyan-800 text-cyan-200 border border-cyan-700/60 rounded-xl text-xs font-bold flex items-center space-x-1.5 transition"
          >
            <Download className="w-4 h-4" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Printable Report Document Card */}
      <div className="bg-slate-900/95 border border-slate-800 rounded-3xl p-6 sm:p-10 space-y-8 shadow-xl print:bg-white print:text-black print:border-none print:shadow-none print:p-0">
        {/* Document Header */}
        <div className="border-b border-slate-800 print:border-slate-300 pb-6 flex flex-col sm:flex-row sm:items-start justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <span className="text-[11px] font-mono font-bold tracking-widest text-cyan-400 print:text-cyan-800 uppercase">
                DEFENSIVE CYBERSECURITY INTELLIGENCE & THREAT MODELING
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-100 print:text-black tracking-tight">
              {project?.name || 'Authorized Security Scope'}
            </h1>
            <p className="text-xs font-mono text-slate-400 print:text-slate-600 mt-1">
              Authorized Scope: <strong className="text-slate-200 print:text-slate-800">{project?.targetScope || '*.internal'}</strong>
            </p>
          </div>

          <div className="text-right sm:self-center font-mono text-xs text-slate-400 print:text-slate-600 space-y-0.5">
            <div>Sign-off: <strong className="text-slate-200 print:text-slate-800">{project?.authorizedBy || 'Authorized Officer'}</strong></div>
            <div>Date: {new Date(report.generatedAt || Date.now()).toLocaleDateString()}</div>
          </div>
        </div>

        {/* Executive Summary & Threat Posture */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-slate-100 print:text-black uppercase tracking-wider font-mono">
            1. Executive Summary & Threat Posture
          </h2>
          <div className="bg-slate-950 p-4.5 rounded-2xl border border-slate-800 print:bg-slate-100 print:border-slate-300 grid grid-cols-2 sm:grid-cols-4 gap-4 text-center font-mono text-xs">
            <div>
              <span className="text-slate-500 print:text-slate-700 block text-[10px]">POSTURE RATING</span>
              <span className="text-base font-bold text-rose-400 print:text-rose-700">
                {metrics?.postureRating || 'SECURE POSTURE'}
              </span>
            </div>
            <div>
              <span className="text-slate-500 print:text-slate-700 block text-[10px]">AVG PATH RISK</span>
              <span className="text-base font-bold text-cyan-400 print:text-cyan-800">
                {metrics?.averageContextualRisk || 0}/100
              </span>
            </div>
            <div>
              <span className="text-slate-500 print:text-slate-700 block text-[10px]">CRITICAL CHAINS</span>
              <span className="text-base font-bold text-rose-400 print:text-rose-700">
                {metrics?.criticalAttackPaths || 0} Active
              </span>
            </div>
            <div>
              <span className="text-slate-500 print:text-slate-700 block text-[10px]">CANONICAL FINDINGS</span>
              <span className="text-base font-bold text-slate-200 print:text-slate-900">
                {metrics?.totalFindings || 0} Issues
              </span>
            </div>
          </div>
          <p className="text-xs text-slate-300 print:text-slate-700 leading-relaxed">
            The security assessment conducted across authorized scope {project?.targetScope} identified {metrics?.totalFindings || 0} canonical security findings consolidated across multi-source scanner logs. Contextual risk analysis revealed {topAttackPaths.length} multi-stage attack paths presenting viable pivot chains to sensitive backend assets.
          </p>
        </div>

        {/* High-Risk Assets Exposure */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-slate-100 print:text-black uppercase tracking-wider font-mono">
            2. High-Risk Asset Exposure
          </h2>
          {highRiskAssets.length > 0 ? (
            <div className="overflow-x-auto rounded-xl border border-slate-800 print:border-slate-300">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950 print:bg-slate-200 text-slate-400 print:text-slate-700">
                  <tr>
                    <th className="p-3">Asset / Host</th>
                    <th className="p-3">Finding Count</th>
                    <th className="p-3">Max Severity</th>
                    <th className="p-3">Critical Paths Affected</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 print:divide-slate-300 text-slate-300 print:text-slate-800 bg-slate-950/40">
                  {highRiskAssets.map((a, i) => (
                    <tr key={i}>
                      <td className="p-3 font-bold text-slate-200 print:text-slate-900">{a.asset}</td>
                      <td className="p-3">{a.findingCount}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                          a.maxSeverity === 'Critical' ? 'bg-rose-950 text-rose-300' : 'bg-amber-950 text-amber-300'
                        }`}>
                          {a.maxSeverity}
                        </span>
                      </td>
                      <td className="p-3">{a.criticalPathsCount}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-xs text-slate-500 font-mono italic">No asset exposure records currently identified.</p>
          )}
        </div>

        {/* Top Attack Paths */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-slate-100 print:text-black uppercase tracking-wider font-mono">
            3. Prioritized Multi-Stage Attack Paths
          </h2>
          {topAttackPaths.length > 0 ? (
            <div className="space-y-3">
              {topAttackPaths.map((path, i) => (
                <div
                  key={path.id}
                  className="bg-slate-950 p-4 rounded-xl border border-slate-800 print:bg-slate-50 print:border-slate-300 space-y-2 text-xs"
                >
                  <div className="flex items-center justify-between font-mono">
                    <span className="font-bold text-slate-200 print:text-black">
                      Chain #{i + 1}: {path.title}
                    </span>
                    <span className="text-rose-400 print:text-rose-700 font-bold">
                      Risk {path.contextualScore}/100 • {path.severity}
                    </span>
                  </div>
                  <p className="text-slate-400 print:text-slate-600 leading-relaxed">{path.summary}</p>
                  <div className="text-[11px] font-mono text-cyan-400 print:text-cyan-800 bg-slate-900/60 p-2 rounded">
                    Node Sequence: {(path.nodes || []).map(n => n.label).join(' → ')}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-500 font-mono italic">No attack paths currently correlated.</p>
          )}
        </div>

        {/* High-Leverage Remediation Roadmap */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-slate-100 print:text-black uppercase tracking-wider font-mono">
            4. High-Leverage Remediation Roadmap
          </h2>
          {prioritizedRemediations.length > 0 ? (
            <div className="space-y-2">
              {prioritizedRemediations.map((rem) => (
                <div
                  key={rem.id}
                  className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 print:bg-slate-50 print:border-slate-300 flex items-start justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="font-bold text-slate-200 print:text-black">
                      {rem.priority} • {rem.title}
                    </div>
                    <div className="text-slate-400 print:text-slate-600 font-mono text-[11px]">
                      Target Asset: {rem.affectedAsset || 'General Scope'}
                    </div>
                  </div>
                  <span className="font-mono text-emerald-400 print:text-emerald-700 font-bold bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-900/50 whitespace-nowrap">
                    {rem.estimatedRiskReductionPercent || (rem as any).riskReductionPct || 0}% Risk Drop
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-500 font-mono italic">No remediation tasks currently generated.</p>
          )}
        </div>

        {/* Methodology & Constraints */}
        <div className="space-y-2 pt-4 border-t border-slate-800 print:border-slate-300 text-[11px] text-slate-500 print:text-slate-600 leading-relaxed font-mono">
          <p>
            <strong>Assessment Methodology:</strong> {report.methodology || 'Defensive correlation and deterministic threat modeling.'}
          </p>
          <p>
            <strong>Defensive Boundary & AI Constraints:</strong> {report.aiLimitations || 'All findings derived from authorized scanner logs.'}
          </p>
        </div>
      </div>
    </div>
  );
};

import React, { useState, useEffect } from 'react';
import { AssessmentReport } from '../types';
import { FileText, Printer, Download, ShieldCheck, AlertTriangle, Route, Lock, CheckCircle2, RefreshCw } from 'lucide-react';

interface ReportViewProps {
  projectId: string;
}

export const ReportView: React.FC<ReportViewProps> = ({ projectId }) => {
  const [report, setReport] = useState<AssessmentReport | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    setIsLoading(true);
    fetch(`/api/projects/${projectId}/report`)
      .then(res => res.json())
      .then(data => {
        setReport(data);
        setIsLoading(false);
      })
      .catch(() => setIsLoading(false));
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
    a.download = `security-report-${report.project.name.toLowerCase().replace(/\s+/g, '-')}-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isLoading) {
    return (
      <div className="p-12 text-center text-slate-400">
        <RefreshCw className="w-8 h-8 mx-auto animate-spin text-cyan-400 mb-2" />
        <p>Compiling executive security assessment report...</p>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="p-8 text-center text-slate-400">
        <p>Unable to generate report at this time.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Top Action Bar (hidden when printing) */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 print:hidden bg-slate-900 border border-slate-800 p-4 rounded-xl shadow-sm">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <span>Executive & Technical Security Posture Report</span>
          </h2>
          <p className="text-xs text-slate-400">
            Generated on {new Date(report.generatedAt).toLocaleString()}
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            id="print-report-btn"
            onClick={handlePrint}
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition"
          >
            <Printer className="w-4 h-4" />
            <span>Print Report</span>
          </button>
          <button
            id="export-json-btn"
            onClick={handleExportJson}
            className="px-3.5 py-2 bg-cyan-900 hover:bg-cyan-800 text-cyan-200 border border-cyan-700/60 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition"
          >
            <Download className="w-4 h-4" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Printable Report Document Card */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-10 space-y-8 shadow-md print:bg-white print:text-black print:border-none print:shadow-none print:p-0">
        {/* Document Header */}
        <div className="border-b border-slate-800 print:border-slate-300 pb-6 flex flex-col sm:flex-row sm:items-start justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <span className="text-xs font-mono font-bold tracking-widest text-cyan-400 print:text-cyan-800 uppercase">
                CYBERSECURITY INTELLIGENCE & THREAT MODELING
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-100 print:text-black">
              {report.project.name}
            </h1>
            <p className="text-xs font-mono text-slate-400 print:text-slate-600 mt-1">
              Authorized Scope: <strong className="text-slate-300 print:text-slate-800">{report.project.targetScope}</strong>
            </p>
          </div>

          <div className="text-right sm:self-center font-mono text-xs text-slate-400 print:text-slate-600">
            <div>Sign-off: {report.project.authorizedBy}</div>
            <div>Date: {new Date(report.generatedAt).toLocaleDateString()}</div>
          </div>
        </div>

        {/* Executive Summary & Posture Rating */}
        <div className="space-y-3">
          <h2 className="text-base font-bold text-slate-100 print:text-black uppercase tracking-wider text-xs">
            1. Executive Summary & Threat Posture
          </h2>
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 print:bg-slate-100 print:border-slate-300 grid grid-cols-2 sm:grid-cols-4 gap-4 text-center font-mono text-xs">
            <div>
              <span className="text-slate-500 print:text-slate-700 block text-[10px]">POSTURE RATING</span>
              <span className="text-base font-bold text-rose-400 print:text-rose-700">
                {report.metrics.postureRating}
              </span>
            </div>
            <div>
              <span className="text-slate-500 print:text-slate-700 block text-[10px]">AVERAGE PATH RISK</span>
              <span className="text-base font-bold text-cyan-400 print:text-cyan-800">
                {report.metrics.averageContextualRisk}/100
              </span>
            </div>
            <div>
              <span className="text-slate-500 print:text-slate-700 block text-[10px]">CRITICAL CHAINS</span>
              <span className="text-base font-bold text-rose-400 print:text-rose-700">
                {report.metrics.criticalAttackPaths} Active
              </span>
            </div>
            <div>
              <span className="text-slate-500 print:text-slate-700 block text-[10px]">CANONICAL VULNS</span>
              <span className="text-base font-bold text-slate-200 print:text-slate-900">
                {report.metrics.totalFindings} Issues
              </span>
            </div>
          </div>
          <p className="text-xs text-slate-300 print:text-slate-700 leading-relaxed">
            The security assessment conducted across authorized scope {report.project.targetScope} identified {report.metrics.totalFindings} canonical security findings consolidated across multi-source scanner logs. Contextual risk analysis revealed {report.topAttackPaths.length} multi-stage attack paths presenting viable pivot chains to sensitive backend assets.
          </p>
        </div>

        {/* High-Risk Assets Exposure */}
        <div className="space-y-3">
          <h2 className="text-base font-bold text-slate-100 print:text-black uppercase tracking-wider text-xs">
            2. High-Risk Asset Exposure
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono border border-slate-800 print:border-slate-300">
              <thead className="bg-slate-950 print:bg-slate-200 text-slate-400 print:text-slate-700">
                <tr>
                  <th className="p-2.5">Asset / Host</th>
                  <th className="p-2.5">Finding Count</th>
                  <th className="p-2.5">Max Severity</th>
                  <th className="p-2.5">Critical Paths Affected</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 print:divide-slate-300 text-slate-300 print:text-slate-800">
                {report.highRiskAssets.map((a, i) => (
                  <tr key={i}>
                    <td className="p-2.5 font-bold">{a.asset}</td>
                    <td className="p-2.5">{a.findingCount}</td>
                    <td className="p-2.5">{a.maxSeverity}</td>
                    <td className="p-2.5">{a.criticalPathsCount}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top Attack Paths */}
        <div className="space-y-3">
          <h2 className="text-base font-bold text-slate-100 print:text-black uppercase tracking-wider text-xs">
            3. Prioritized Multi-Stage Attack Paths
          </h2>
          <div className="space-y-3">
            {report.topAttackPaths.map((path, i) => (
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
                <p className="text-slate-400 print:text-slate-600">{path.summary}</p>
                <div className="text-[11px] font-mono text-cyan-400 print:text-cyan-800">
                  Node Sequence: {path.nodes.map(n => n.label).join(' → ')}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* High-Leverage Remediation Roadmap */}
        <div className="space-y-3">
          <h2 className="text-base font-bold text-slate-100 print:text-black uppercase tracking-wider text-xs">
            4. High-Leverage Remediation Roadmap
          </h2>
          <div className="space-y-2">
            {report.prioritizedRemediations.map((rem, i) => (
              <div
                key={rem.id}
                className="p-3 rounded-lg bg-slate-950 border border-slate-800 print:bg-slate-50 print:border-slate-300 flex items-start justify-between gap-3 text-xs"
              >
                <div className="space-y-0.5">
                  <div className="font-bold text-slate-200 print:text-black">
                    {rem.priority} • {rem.title}
                  </div>
                  <div className="text-slate-400 print:text-slate-600">
                    Asset: {rem.affectedAsset} • Effort: {rem.effort}
                  </div>
                </div>
                <span className="font-mono text-emerald-400 print:text-emerald-700 font-bold whitespace-nowrap">
                  {rem.riskReductionPct}% Risk Reduction
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Methodology & AI Limitations */}
        <div className="space-y-2 pt-4 border-t border-slate-800 print:border-slate-300 text-[11px] text-slate-500 print:text-slate-600 leading-relaxed font-mono">
          <p>
            <strong>Assessment Methodology:</strong> {report.methodology}
          </p>
          <p>
            <strong>Defensive Boundary & AI Constraints:</strong> {report.aiLimitations}
          </p>
        </div>
      </div>
    </div>
  );
};

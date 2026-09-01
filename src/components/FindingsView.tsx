import React, { useState, useMemo } from 'react';
import { NormalizedFinding, Severity, FindingStatus } from '../types';
import { Search, Layers, Sparkles, X, Code2, Copy, Check } from 'lucide-react';

interface FindingsViewProps {
  findings: NormalizedFinding[];
  onUpdateStatus: (findingId: string, status: FindingStatus) => void;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  findings,
  onUpdateStatus,
}) => {
  const [search, setSearch] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [selectedAsset, setSelectedAsset] = useState<string>('ALL');
  const [viewMode, setViewMode] = useState<'canonical' | 'raw'>('canonical');
  const [selectedFinding, setSelectedFinding] = useState<NormalizedFinding | null>(null);
  const [copiedPayload, setCopiedPayload] = useState(false);

  // Asset list
  const assets = useMemo(() => {
    return Array.from(new Set((findings || []).map(f => f.asset)));
  }, [findings]);

  // Filtered findings
  const filteredFindings = useMemo(() => {
    return (findings || []).filter(f => {
      if (!f) return false;
      if (selectedSeverity !== 'ALL' && f.severity !== selectedSeverity) return false;
      if (selectedStatus !== 'ALL' && f.status !== selectedStatus) return false;
      if (selectedAsset !== 'ALL' && f.asset !== selectedAsset) return false;
      if (search) {
        const q = search.toLowerCase();
        const matchTitle = f.title?.toLowerCase().includes(q);
        const matchEnd = f.endpoint?.toLowerCase().includes(q);
        const matchCwe = f.cwe?.toLowerCase().includes(q);
        const matchCve = f.cve?.toLowerCase().includes(q);
        const matchAsset = f.asset?.toLowerCase().includes(q);
        if (!matchTitle && !matchEnd && !matchCwe && !matchCve && !matchAsset) return false;
      }
      return true;
    });
  }, [findings, selectedSeverity, selectedStatus, selectedAsset, search]);

  const rawCountTotal = (findings || []).reduce((acc, f) => acc + (f?.sourceCount || 1), 0);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            <span>Normalized Security Findings Matrix</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Heterogeneous scanner findings normalized into canonical records with deterministic deduplication & calibrated AI triage.
          </p>
        </div>

        {/* Canonical vs Raw Toggle */}
        <div className="flex items-center space-x-1.5 bg-slate-900 border border-slate-800 p-1 rounded-xl self-start md:self-auto text-xs">
          <button
            id="view-canonical-btn"
            onClick={() => setViewMode('canonical')}
            className={`px-3 py-1.5 rounded-lg font-bold transition ${
              viewMode === 'canonical'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Canonical ({findings.length})
          </button>
          <button
            id="view-raw-btn"
            onClick={() => setViewMode('raw')}
            className={`px-3 py-1.5 rounded-lg font-bold transition ${
              viewMode === 'raw'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Raw Events ({rawCountTotal})
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="cyber-card rounded-xl p-3.5 flex flex-wrap items-center justify-between gap-3 shadow-sm border border-slate-800 text-xs">
        {/* Search */}
        <div className="relative flex-1 min-w-[220px] max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            id="findings-search"
            type="text"
            placeholder="Search by title, CWE, CVE, endpoint, or asset..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 placeholder-slate-500"
          />
        </div>

        {/* Filter Dropdowns */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Severity */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-slate-950 text-slate-200 border border-slate-800 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Info">Info</option>
          </select>

          {/* Status */}
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="bg-slate-950 text-slate-200 border border-slate-800 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="verified_fixed">Verified Fixed</option>
            <option value="false_positive">False Positive</option>
          </select>

          {/* Asset */}
          {assets.length > 1 && (
            <select
              value={selectedAsset}
              onChange={(e) => setSelectedAsset(e.target.value)}
              className="bg-slate-950 text-slate-200 border border-slate-800 rounded-lg px-2.5 py-1.5 max-w-[150px] truncate focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Assets</option>
              {assets.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          )}

          {(search || selectedSeverity !== 'ALL' || selectedStatus !== 'ALL' || selectedAsset !== 'ALL') && (
            <button
              onClick={() => {
                setSearch('');
                setSelectedSeverity('ALL');
                setSelectedStatus('ALL');
                setSelectedAsset('ALL');
              }}
              className="text-cyan-400 hover:text-cyan-300 underline px-1 font-semibold"
            >
              Clear Filters
            </button>
          )}
        </div>
      </div>

      {/* Findings Table */}
      <div className="cyber-card rounded-2xl overflow-hidden shadow-lg border border-slate-800">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/90 text-slate-400 font-mono uppercase text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-3.5 px-4 font-semibold">Severity</th>
                <th className="py-3.5 px-4 font-semibold">Finding & Category</th>
                <th className="py-3.5 px-4 font-semibold">Asset / Endpoint</th>
                <th className="py-3.5 px-4 font-semibold">Identifiers</th>
                <th className="py-3.5 px-4 font-semibold">AI Triage Confidence</th>
                <th className="py-3.5 px-4 font-semibold">Provenance</th>
                <th className="py-3.5 px-4 font-semibold">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500 font-mono">
                    No security findings match your filter criteria.
                  </td>
                </tr>
              ) : (
                filteredFindings.map((finding) => (
                  <tr
                    key={finding.id}
                    onClick={() => setSelectedFinding(finding)}
                    className="hover:bg-slate-800/40 cursor-pointer transition"
                  >
                    {/* Severity */}
                    <td className="py-3.5 px-4 font-mono font-bold whitespace-nowrap">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                          finding.severity === 'Critical'
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : finding.severity === 'High'
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : finding.severity === 'Medium'
                            ? 'bg-yellow-950 text-yellow-300 border border-yellow-800'
                            : finding.severity === 'Low'
                            ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {finding.severity}
                      </span>
                    </td>

                    {/* Title & Category */}
                    <td className="py-3.5 px-4 max-w-xs sm:max-w-sm">
                      <div className="font-bold text-slate-100 truncate">{finding.title}</div>
                      <div className="text-[11px] text-slate-400 truncate mt-0.5">{finding.vulnerabilityCategory}</div>
                    </td>

                    {/* Asset & Endpoint */}
                    <td className="py-3.5 px-4 font-mono text-slate-300 max-w-[200px] truncate">
                      <div className="text-slate-200 font-semibold truncate">{finding.asset}</div>
                      <div className="text-slate-400 text-[11px] truncate">{finding.endpoint}</div>
                    </td>

                    {/* Identifiers (CWE, CVE) */}
                    <td className="py-3.5 px-4 font-mono text-[11px] whitespace-nowrap space-x-1">
                      {finding.cwe && (
                        <span className="px-1.5 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800">
                          {finding.cwe}
                        </span>
                      )}
                      {finding.cve && (
                        <span className="px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                          {finding.cve}
                        </span>
                      )}
                    </td>

                    {/* AI Calibrated Confidence */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {finding.aiTriage ? (
                        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-slate-950 text-cyan-300 border border-cyan-900/60 font-mono text-[11px] font-semibold">
                          <Sparkles className="w-3 h-3 text-cyan-400" />
                          <span>{finding.aiTriage.calibratedConfidence}</span>
                        </span>
                      ) : (
                        <span className="text-slate-500 font-mono">{finding.confidence}</span>
                      )}
                    </td>

                    {/* Provenance */}
                    <td className="py-3.5 px-4 font-mono text-slate-400 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 text-[11px]">
                        {finding.sourceCount || 1} {(finding.sourceCount || 1) === 1 ? 'source' : 'sources'}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold capitalize ${
                          finding.status === 'verified_fixed'
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            : finding.status === 'in_progress'
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : finding.status === 'false_positive'
                            ? 'bg-slate-800 text-slate-400'
                            : 'bg-rose-950/70 text-rose-300 border border-rose-900/50'
                        }`}
                      >
                        {finding.status.replace('_', ' ')}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Finding Detail Inspection Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-3xl max-h-[90vh] overflow-y-auto p-6 space-y-5 shadow-2xl">
            {/* Modal Header */}
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center space-x-2 mb-1">
                  <span
                    className={`px-2.5 py-0.5 rounded text-xs font-bold uppercase font-mono ${
                      selectedFinding.severity === 'Critical'
                        ? 'bg-rose-950 text-rose-300 border border-rose-800'
                        : selectedFinding.severity === 'High'
                        ? 'bg-amber-950 text-amber-300 border border-amber-800'
                        : 'bg-yellow-950 text-yellow-300 border border-yellow-800'
                    }`}
                  >
                    {selectedFinding.severity}
                  </span>
                  <span className="text-xs font-mono text-slate-400">{selectedFinding.id}</span>
                </div>
                <h3 className="text-lg font-bold text-slate-100">{selectedFinding.title}</h3>
                <p className="text-xs font-mono text-cyan-400 mt-0.5">
                  {selectedFinding.asset} • {selectedFinding.endpoint}
                </p>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* AI Triage Section */}
            {selectedFinding.aiTriage && (
              <div className="bg-slate-950 border border-cyan-900/50 rounded-xl p-4 space-y-2.5">
                <div className="flex items-center space-x-2 text-cyan-400 font-bold text-xs">
                  <Sparkles className="w-4 h-4" />
                  <span>AI Contextual Triage & Evidence Assessment</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  <div>
                    <strong className="text-slate-300">Calibrated Confidence:</strong>{' '}
                    <span className="font-mono text-cyan-300">
                      {selectedFinding.aiTriage.calibratedConfidence}
                    </span>
                  </div>
                  <div>
                    <strong className="text-slate-300">Evidence Quality:</strong>{' '}
                    <span className="font-mono text-slate-200">
                      {selectedFinding.aiTriage.evidenceQuality}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  <strong>Business Blast Radius:</strong> {selectedFinding.aiTriage.businessImpact}
                </p>
                <p className="text-xs text-slate-400 font-mono bg-slate-900 p-2.5 rounded-lg">
                  {selectedFinding.aiTriage.reasoning}
                </p>
              </div>
            )}

            {/* Description */}
            {selectedFinding.description && (
              <div className="space-y-1">
                <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Vulnerability Overview</h4>
                <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
                  {selectedFinding.description}
                </p>
              </div>
            )}

            {/* Captured Scanner Evidence */}
            {selectedFinding.evidence && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <h4 className="font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-1.5">
                    <Code2 className="w-4 h-4 text-cyan-400" />
                    <span>Captured Security Evidence</span>
                  </h4>
                  <button
                    onClick={() => handleCopy(selectedFinding.evidence?.payload || selectedFinding.evidence?.request || '')}
                    className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                  >
                    {copiedPayload ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedPayload ? 'Copied' : 'Copy Payload'}</span>
                  </button>
                </div>
                <pre className="bg-slate-950 p-3.5 rounded-xl text-xs font-mono text-slate-300 overflow-x-auto max-h-48 border border-slate-800 whitespace-pre-wrap">
                  {selectedFinding.evidence.payload || selectedFinding.evidence.request || selectedFinding.evidence.rawOutput || 'No payload trace provided.'}
                </pre>
              </div>
            )}

            {/* Provenance List */}
            <div className="space-y-2 pt-2 border-t border-slate-800">
              <h4 className="text-xs font-bold text-slate-200">
                Consolidated Scanner Provenance ({selectedFinding.sourceCount || 1} items)
              </h4>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {(selectedFinding.provenance || []).map((src, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between text-[11px] font-mono p-2 rounded-lg bg-slate-950 border border-slate-800/80 text-slate-300"
                  >
                    <span>Scanner: <strong>{src.scanner}</strong></span>
                    <span className="text-slate-500">{new Date(src.timestamp).toLocaleTimeString()}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Status Switcher Footer */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-800">
              <div className="flex items-center space-x-2 text-xs">
                <span className="text-slate-400 font-semibold">Update Status:</span>
                <select
                  value={selectedFinding.status}
                  onChange={(e) => {
                    const st = e.target.value as FindingStatus;
                    onUpdateStatus(selectedFinding.id, st);
                    setSelectedFinding({ ...selectedFinding, status: st });
                  }}
                  className="bg-slate-950 text-slate-200 border border-slate-800 rounded-lg px-2.5 py-1 text-xs font-semibold focus:outline-none focus:border-cyan-500"
                >
                  <option value="open">Open</option>
                  <option value="in_progress">In Progress</option>
                  <option value="verified_fixed">Verified Fixed</option>
                  <option value="false_positive">False Positive</option>
                </select>
              </div>

              <button
                onClick={() => setSelectedFinding(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-bold transition"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

import React, { useState } from 'react';
import { Scan } from '../types';
import { UploadCloud, FileText, CheckCircle2, AlertCircle, RefreshCw, Layers, ShieldCheck, Code2, Terminal, Cpu, FileSpreadsheet } from 'lucide-react';

interface IngestionHubViewProps {
  projectId: string;
  onUploadScan: (filename: string, rawContent: string) => Promise<any>;
  onProcessScan: (scanId: string) => Promise<any>;
  onNavigateTab: (tab: string) => void;
  scans: Scan[];
}

export const IngestionHubView: React.FC<IngestionHubViewProps> = ({
  projectId,
  onUploadScan,
  onProcessScan,
  onNavigateTab,
  scans,
}) => {
  const [dragOver, setDragOver] = useState(false);
  const [pasteContent, setPasteContent] = useState('');
  const [pasteFilename, setPasteFilename] = useState('custom-scan.json');
  const [isProcessing, setIsProcessing] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleFileUpload = async (file: File) => {
    setErrorMessage(null);
    setStatusMessage(`Reading ${file.name}...`);
    setIsProcessing(true);

    try {
      const text = await file.text();
      setStatusMessage(`Parsing & normalizing ${file.name}...`);
      const result = await onUploadScan(file.name, text);

      setStatusMessage(`Running AI Triage and Attack-Path Correlation...`);
      await onProcessScan(result.scan.id);

      setStatusMessage(`Successfully parsed ${file.name}! Directing to triage dashboard...`);
      setTimeout(() => {
        setStatusMessage(null);
        onNavigateTab('dashboard');
      }, 1200);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to upload and parse scan file.');
    } finally {
      setIsProcessing(false);
    }
  };

  const handlePasteSubmit = async () => {
    if (!pasteContent.trim()) return;
    setErrorMessage(null);
    setIsProcessing(true);
    setStatusMessage('Parsing pasted scan content...');

    try {
      const result = await onUploadScan(pasteFilename || 'pasted-scan.json', pasteContent);
      setStatusMessage('Correlating attack paths & risk scoring...');
      await onProcessScan(result.scan.id);
      setStatusMessage('Scan parsed and prioritized successfully!');
      setPasteContent('');
      setTimeout(() => {
        setStatusMessage(null);
        onNavigateTab('dashboard');
      }, 1200);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to parse pasted scan.');
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
          <UploadCloud className="w-5 h-5 text-cyan-400" />
          <span>Security Scanner Ingestion</span>
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Upload raw scan results from OWASP ZAP, Nuclei, Semgrep, Trivy, Nmap, or generic CSV/JSON logs into unified, deduplicated intelligence.
        </p>
      </div>

      {/* Status or Error Notifications */}
      {statusMessage && (
        <div className="bg-cyan-950/80 border border-cyan-800 text-cyan-200 p-4 rounded-xl flex items-center space-x-3 text-xs">
          <RefreshCw className="w-4 h-4 animate-spin text-cyan-400 shrink-0" />
          <span>{statusMessage}</span>
        </div>
      )}

      {errorMessage && (
        <div className="bg-rose-950/80 border border-rose-800 text-rose-200 p-4 rounded-xl flex items-center space-x-3 text-xs">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Ingestion Area: Drag-and-Drop & Paste Interface */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left 7 Cols: Upload Box & Paste Area */}
        <div className="lg:col-span-7 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
            <h3 className="text-sm font-bold text-slate-200 flex items-center space-x-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              <span>Upload Security Scan File</span>
            </h3>

            {/* Dropzone */}
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragOver(false);
                if (e.dataTransfer.files?.[0]) {
                  handleFileUpload(e.dataTransfer.files[0]);
                }
              }}
              className={`border-2 border-dashed rounded-xl p-8 text-center transition cursor-pointer ${
                dragOver
                  ? 'border-cyan-500 bg-cyan-950/30'
                  : 'border-slate-700 hover:border-slate-600 bg-slate-950/50'
              }`}
              onClick={() => document.getElementById('file-upload-input')?.click()}
            >
              <input
                id="file-upload-input"
                type="file"
                accept=".json,.csv,.txt,.xml"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files?.[0]) {
                    handleFileUpload(e.target.files[0]);
                  }
                }}
              />
              <UploadCloud className="w-10 h-10 mx-auto text-cyan-400 mb-2" />
              <p className="text-sm font-semibold text-slate-200">
                Drag & Drop scanner output here, or click to browse
              </p>
              <p className="text-xs text-slate-400 mt-1 font-mono">
                Supports: .json, .csv, .xml, .txt (ZAP, Nuclei, Semgrep, Trivy, Nmap, CSV)
              </p>
            </div>

            {/* Manual Raw Content Paste Mode */}
            <div className="pt-2 space-y-2 border-t border-slate-800">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-300">Or Paste Raw Scanner JSON/CSV Logs:</span>
                <input
                  type="text"
                  value={pasteFilename}
                  onChange={(e) => setPasteFilename(e.target.value)}
                  placeholder="custom-scan.json"
                  className="bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 px-2 py-0.5 rounded w-40"
                />
              </div>
              <textarea
                rows={5}
                value={pasteContent}
                onChange={(e) => setPasteContent(e.target.value)}
                placeholder='Paste raw JSON, JSONL, XML, or CSV scan text directly here...'
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500 placeholder-slate-600"
              />
              <button
                id="paste-submit-btn"
                onClick={handlePasteSubmit}
                disabled={!pasteContent.trim() || isProcessing}
                className="w-full py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-600 text-white rounded-lg text-xs font-bold transition shadow-sm"
              >
                {isProcessing ? 'Processing & Correlating...' : 'Parse & Process Pasted Output'}
              </button>
            </div>
          </div>
        </div>

        {/* Right 5 Cols: Supported Formats & Reference Guide */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
            <h3 className="text-sm font-bold text-slate-200 flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>Supported Scanner Formats</span>
            </h3>
            <p className="text-xs text-slate-400">
              The ingestion engine automatically detects the scanner syntax, normalizes CWE/CVSS attributes, and executes deterministic deduplication:
            </p>

            <div className="space-y-2.5 text-xs font-mono">
              <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-2.5 space-y-1">
                <div className="flex items-center justify-between text-slate-200 font-bold">
                  <span className="flex items-center space-x-1.5 text-cyan-300">
                    <Terminal className="w-3.5 h-3.5" />
                    <span>OWASP ZAP</span>
                  </span>
                  <span className="text-[10px] text-slate-500">JSON Report</span>
                </div>
                <p className="text-slate-400 text-[11px] font-sans">
                  Exports from ZAP GUI (<code className="text-cyan-300">Report &gt; Generate Report (JSON)</code>) or ZAP automation framework.
                </p>
              </div>

              <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-2.5 space-y-1">
                <div className="flex items-center justify-between text-slate-200 font-bold">
                  <span className="flex items-center space-x-1.5 text-cyan-300">
                    <Code2 className="w-3.5 h-3.5" />
                    <span>ProjectDiscovery Nuclei</span>
                  </span>
                  <span className="text-[10px] text-slate-500">JSON / JSONL</span>
                </div>
                <p className="text-slate-400 text-[11px] font-sans">
                  Command: <code className="text-cyan-300">nuclei -target &lt;domain&gt; -json -o output.json</code>
                </p>
              </div>

              <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-2.5 space-y-1">
                <div className="flex items-center justify-between text-slate-200 font-bold">
                  <span className="flex items-center space-x-1.5 text-cyan-300">
                    <Cpu className="w-3.5 h-3.5" />
                    <span>Semgrep SAST</span>
                  </span>
                  <span className="text-[10px] text-slate-500">JSON</span>
                </div>
                <p className="text-slate-400 text-[11px] font-sans">
                  Command: <code className="text-cyan-300">semgrep scan --json -o semgrep-findings.json</code>
                </p>
              </div>

              <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-2.5 space-y-1">
                <div className="flex items-center justify-between text-slate-200 font-bold">
                  <span className="flex items-center space-x-1.5 text-cyan-300">
                    <Layers className="w-3.5 h-3.5" />
                    <span>Aqua Trivy (Container/SCA)</span>
                  </span>
                  <span className="text-[10px] text-slate-500">JSON</span>
                </div>
                <p className="text-slate-400 text-[11px] font-sans">
                  Command: <code className="text-cyan-300">trivy fs --format json -o trivy.json .</code>
                </p>
              </div>

              <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-2.5 space-y-1">
                <div className="flex items-center justify-between text-slate-200 font-bold">
                  <span className="flex items-center space-x-1.5 text-cyan-300">
                    <FileSpreadsheet className="w-3.5 h-3.5" />
                    <span>Generic CSV / JSON Logs</span>
                  </span>
                  <span className="text-[10px] text-slate-500">CSV / JSON Array</span>
                </div>
                <p className="text-slate-400 text-[11px] font-sans">
                  Standard columns: <code className="text-cyan-300">title, severity, asset, endpoint, cwe, description</code>.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Imported Scans History Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-3">
        <h3 className="text-sm font-bold text-slate-200 flex items-center justify-between">
          <span>Project Ingestion History ({scans.length})</span>
          <span className="text-xs font-mono text-slate-400">Audit Provenance Log</span>
        </h3>

        {scans.length === 0 ? (
          <p className="text-xs text-slate-500 py-6 text-center font-mono">
            No scans imported into this project yet. Upload or paste a scanner file above to begin.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Filename</th>
                  <th className="py-2.5 px-3">Scanner Type</th>
                  <th className="py-2.5 px-3">Raw Findings</th>
                  <th className="py-2.5 px-3">Deduplicated</th>
                  <th className="py-2.5 px-3">Critical / High</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-3 font-semibold text-slate-200">{scan.filename}</td>
                    <td className="py-2.5 px-3 text-cyan-300">{scan.scannerType}</td>
                    <td className="py-2.5 px-3 text-slate-400">{scan.totalRawFindings}</td>
                    <td className="py-2.5 px-3 text-emerald-400 font-bold">{scan.deduplicatedCount}</td>
                    <td className="py-2.5 px-3">
                      <span className="text-rose-400 font-bold">{scan.summary.critical} Crit</span> /{' '}
                      <span className="text-amber-400 font-bold">{scan.summary.high} High</span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800 uppercase">
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-500">
                      {new Date(scan.uploadedAt).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

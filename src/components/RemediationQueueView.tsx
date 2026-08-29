import React, { useState } from 'react';
import { RemediationItem, RemediationPriority } from '../types';
import { ShieldCheck, Sparkles, CheckCircle2, Clock, Terminal, ArrowRight, Code2, AlertTriangle, X, Check, Lock } from 'lucide-react';
import confetti from 'canvas-confetti';

interface RemediationQueueViewProps {
  remediations: RemediationItem[];
  projectId: string;
  onUpdateStatus: (id: string, status: RemediationItem['status']) => void;
  onGenerateAiGuide: (id: string) => Promise<any>;
}

export const RemediationQueueView: React.FC<RemediationQueueViewProps> = ({
  remediations,
  projectId,
  onUpdateStatus,
  onGenerateAiGuide,
}) => {
  const [selectedItemForAi, setSelectedItemForAi] = useState<RemediationItem | null>(null);
  const [isGeneratingAi, setIsGeneratingAi] = useState(false);
  const [activeTab, setActiveTab] = useState<'all' | 'P0' | 'P1' | 'P2' | 'P3'>('all');

  const filteredItems = remediations.filter(item => {
    if (activeTab === 'all') return true;
    return item.priority.startsWith(activeTab);
  });

  const handleStatusChange = (item: RemediationItem, newStatus: RemediationItem['status']) => {
    onUpdateStatus(item.id, newStatus);
    if (newStatus === 'verified_fixed') {
      try {
        confetti({
          particleCount: 50,
          spread: 60,
          origin: { y: 0.8 },
        });
      } catch {}
    }
  };

  const handleOpenAiAssistant = async (item: RemediationItem) => {
    setSelectedItemForAi(item);
    if (!item.aiGuidance) {
      setIsGeneratingAi(true);
      try {
        const guidance = await onGenerateAiGuide(item.id);
        setSelectedItemForAi({ ...item, aiGuidance: guidance });
      } catch {
      } finally {
        setIsGeneratingAi(false);
      }
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <span>High-Leverage Remediation Queue</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Prioritizing bottleneck fixes that break multiple critical attack paths with minimal operational effort.
          </p>
        </div>

        {/* Priority Filter Tabs */}
        <div className="flex items-center space-x-1.5 bg-slate-900 border border-slate-800 p-1 rounded-lg text-xs self-start sm:self-auto">
          {(['all', 'P0', 'P1', 'P2', 'P3'] as const).map((p) => (
            <button
              key={p}
              onClick={() => setActiveTab(p)}
              className={`px-3 py-1.5 rounded-md font-semibold transition ${
                activeTab === p
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {p === 'all' ? `All (${remediations.length})` : p}
            </button>
          ))}
        </div>
      </div>

      {remediations.length === 0 ? (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-12 text-center text-slate-400">
          <ShieldCheck className="w-12 h-12 mx-auto text-emerald-500 mb-3" />
          <h3 className="text-base font-semibold text-slate-200">No Remediation Tasks in Queue</h3>
          <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
            All vulnerabilities have been resolved or no security scans have been processed yet.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {filteredItems.map((item) => {
            const isFixed = item.status === 'verified_fixed';
            const priorityBadge =
              item.priority.startsWith('P0')
                ? 'bg-rose-950 text-rose-300 border-rose-800'
                : item.priority.startsWith('P1')
                ? 'bg-amber-950 text-amber-300 border-amber-800'
                : item.priority.startsWith('P2')
                ? 'bg-yellow-950 text-yellow-300 border-yellow-800'
                : 'bg-cyan-950 text-cyan-300 border-cyan-800';

            return (
              <div
                key={item.id}
                className={`bg-slate-900/80 border rounded-xl p-5 transition shadow-sm ${
                  isFixed ? 'border-emerald-900/50 opacity-75' : 'border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                  {/* Left Info */}
                  <div className="space-y-2 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`px-2.5 py-0.5 rounded text-xs font-bold font-mono border ${priorityBadge}`}>
                        {item.priority}
                      </span>
                      <span className="text-xs font-mono font-bold text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-900/60">
                        {item.estimatedRiskReductionPercent}% Risk Reduction
                      </span>
                      <span className="text-xs font-mono text-slate-400">
                        Affected Findings: <strong className="text-slate-300">{item.affectedFindingIds.length}</strong>
                      </span>
                      <span className="text-xs font-mono text-slate-400">
                        Attack Paths Eliminated: <strong className="text-cyan-300">{item.pathsEliminatedCount}</strong>
                      </span>
                    </div>

                    <h3 className={`text-base font-bold ${isFixed ? 'line-through text-slate-400' : 'text-slate-100'}`}>
                      {item.title}
                    </h3>
                    <p className="text-xs text-slate-300 leading-relaxed max-w-3xl">
                      {item.engineeringAction}
                    </p>

                    {/* Safeguards Chips */}
                    {item.architecturalSafeguards && item.architecturalSafeguards.length > 0 && (
                      <div className="pt-2 flex flex-wrap items-center gap-1.5 text-[11px] font-mono text-slate-400">
                        <span className="text-slate-500 font-semibold">Safeguards:</span>
                        {item.architecturalSafeguards.map((s, i) => (
                          <span key={i} className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-300">
                            {s}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Right Actions */}
                  <div className="flex flex-col sm:flex-row md:flex-col items-end gap-2 shrink-0">
                    <button
                      id={`ai-guide-btn-${item.id}`}
                      onClick={() => handleOpenAiAssistant(item)}
                      className="w-full sm:w-auto px-3.5 py-2 bg-gradient-to-r from-cyan-900 to-blue-900 hover:from-cyan-800 hover:to-blue-800 text-cyan-100 border border-cyan-700/60 rounded-lg text-xs font-semibold flex items-center justify-center space-x-1.5 transition shadow-sm"
                    >
                      <Sparkles className="w-3.5 h-3.5 text-cyan-300" />
                      <span>AI Remediation Assistant</span>
                    </button>

                    {/* Status Toggle */}
                    <div className="flex items-center space-x-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
                      <button
                        onClick={() => handleStatusChange(item, 'pending')}
                        className={`px-2.5 py-1 rounded font-medium transition ${
                          item.status === 'pending' ? 'bg-slate-800 text-slate-200' : 'text-slate-500 hover:text-slate-300'
                        }`}
                      >
                        Pending
                      </button>
                      <button
                        onClick={() => handleStatusChange(item, 'in_progress')}
                        className={`px-2.5 py-1 rounded font-medium transition ${
                          item.status === 'in_progress' ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'text-slate-500 hover:text-slate-300'
                        }`}
                      >
                        In Progress
                      </button>
                      <button
                        onClick={() => handleStatusChange(item, 'verified_fixed')}
                        className={`px-2.5 py-1 rounded font-medium flex items-center space-x-1 transition ${
                          item.status === 'verified_fixed' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'text-slate-500 hover:text-slate-300'
                        }`}
                      >
                        <Check className="w-3 h-3" />
                        <span>Verified Fixed</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* AI Remediation Guidance Modal / Drawer */}
      {selectedItemForAi && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-4xl max-h-[92vh] overflow-y-auto p-6 space-y-6 shadow-2xl">
            {/* Header */}
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center space-x-2 mb-1">
                  <span className="px-2 py-0.5 rounded text-xs font-bold font-mono bg-cyan-950 text-cyan-300 border border-cyan-800">
                    AI Remediation Guidance
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    {selectedItemForAi.priority}
                  </span>
                </div>
                <h3 className="text-lg font-bold text-slate-100">{selectedItemForAi.title}</h3>
              </div>
              <button
                onClick={() => setSelectedItemForAi(null)}
                className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {isGeneratingAi ? (
              <div className="p-12 text-center text-slate-400 space-y-3">
                <Sparkles className="w-8 h-8 mx-auto text-cyan-400 animate-spin" />
                <p className="font-medium text-slate-200">Synthesizing defensive code patterns & verification steps...</p>
                <p className="text-xs text-slate-500">Consulting defensive security blueprints & CWE catalog</p>
              </div>
            ) : selectedItemForAi.aiGuidance ? (
              <div className="space-y-5 text-xs">
                {/* Root Cause */}
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-1.5">
                  <h4 className="font-bold text-slate-200 flex items-center space-x-1.5">
                    <Lock className="w-4 h-4 text-cyan-400" />
                    <span>Root Cause Explanation</span>
                  </h4>
                  <p className="text-slate-300 leading-relaxed">
                    {selectedItemForAi.aiGuidance.rootCauseExplanation}
                  </p>
                </div>

                {/* Impact Rationale */}
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-1.5">
                  <h4 className="font-bold text-slate-200 flex items-center space-x-1.5">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    <span>Impact & Risk Rationale</span>
                  </h4>
                  <p className="text-slate-300 leading-relaxed">
                    {selectedItemForAi.aiGuidance.impactRationale}
                  </p>
                </div>

                {/* Remediation Blueprint / Code Fix Pattern */}
                <div className="space-y-1.5">
                  <h4 className="font-bold text-slate-200 flex items-center space-x-1.5">
                    <Code2 className="w-4 h-4 text-emerald-400" />
                    <span>Defensive Code Pattern & Engineering Blueprint</span>
                  </h4>
                  <pre className="bg-slate-950 p-4 rounded-xl font-mono text-xs text-emerald-300 border border-slate-800 overflow-x-auto whitespace-pre-wrap">
                    {selectedItemForAi.aiGuidance.remediationBlueprint}
                  </pre>
                </div>

                {/* Verification Steps & Protocols */}
                <div className="bg-slate-950 border border-cyan-950 rounded-xl p-4 space-y-3">
                  <h4 className="font-bold text-cyan-300 flex items-center space-x-1.5">
                    <Terminal className="w-4 h-4 text-cyan-400" />
                    <span>Post-Remediation Verification Protocol</span>
                  </h4>
                  <ul className="space-y-1 text-slate-300 list-disc list-inside">
                    {selectedItemForAi.aiGuidance.verificationSteps?.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ul>
                </div>

                {/* Residual Risk Notes */}
                {selectedItemForAi.aiGuidance.residualRiskNotes && (
                  <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-1.5">
                    <h4 className="font-bold text-slate-200">Residual Risk Notes</h4>
                    <p className="text-slate-400 leading-relaxed">
                      {selectedItemForAi.aiGuidance.residualRiskNotes}
                    </p>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-8 text-center text-slate-400">
                <p>Guidance could not be generated. Please try again.</p>
              </div>
            )}

            {/* Footer */}
            <div className="flex justify-end pt-3 border-t border-slate-800">
              <button
                onClick={() => setSelectedItemForAi(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

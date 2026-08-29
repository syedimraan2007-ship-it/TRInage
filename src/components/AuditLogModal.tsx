import React, { useState, useEffect } from 'react';
import { FileCheck, X, RefreshCw } from 'lucide-react';

interface AuditLogModalProps {
  isOpen: boolean;
  onClose: () => void;
  projectId?: string;
}

export const AuditLogModal: React.FC<AuditLogModalProps> = ({
  isOpen,
  onClose,
  projectId,
}) => {
  const [logs, setLogs] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setIsLoading(true);
      const url = projectId ? `/api/audit-logs?projectId=${projectId}` : '/api/audit-logs';
      fetch(url)
        .then(res => res.json())
        .then(data => {
          setLogs(data);
          setIsLoading(false);
        })
        .catch(() => setIsLoading(false));
    }
  }, [isOpen, projectId]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col p-6 shadow-2xl space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <FileCheck className="w-5 h-5 text-cyan-400" />
            <div>
              <h3 className="text-base font-bold text-slate-100">Assessment Audit Trail</h3>
              <p className="text-xs text-slate-400">Chronological log of scan ingestions, correlations, and status changes</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {isLoading ? (
          <div className="py-12 text-center text-slate-400">
            <RefreshCw className="w-6 h-6 mx-auto animate-spin text-cyan-400 mb-2" />
            <p className="text-xs">Loading audit logs...</p>
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto space-y-2 pr-1">
            {logs.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-8">No audit events recorded yet.</p>
            ) : (
              logs.map((log) => (
                <div
                  key={log.id}
                  className="bg-slate-950 border border-slate-800/80 rounded-lg p-3 text-xs font-mono space-y-1"
                >
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="font-bold text-cyan-300 bg-cyan-950/60 px-1.5 py-0.5 rounded">
                      {log.action}
                    </span>
                    <span className="text-slate-500">
                      {new Date(log.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <p className="text-slate-300">{log.details}</p>
                </div>
              ))
            )}
          </div>
        )}

        <div className="border-t border-slate-800 pt-3 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

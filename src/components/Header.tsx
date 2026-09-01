import React, { useState } from 'react';
import { Project } from '../types';
import { Shield, Plus, FolderKanban, FileCheck, Trash2, AlertCircle } from 'lucide-react';

interface HeaderProps {
  projects: Project[];
  currentProject: Project | null;
  onSelectProject: (p: Project) => void;
  onOpenNewProject: () => void;
  onOpenAuditLogs: () => void;
  onDeleteProject?: (id: string) => Promise<void>;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  counts?: {
    findings?: number;
    attackPaths?: number;
    remediations?: number;
  };
}

export const Header: React.FC<HeaderProps> = ({
  projects,
  currentProject,
  onSelectProject,
  onOpenNewProject,
  onOpenAuditLogs,
  onDeleteProject,
  activeTab,
  setActiveTab,
  counts,
}) => {
  const [isDeleting, setIsDeleting] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  const handleDelete = async () => {
    if (!currentProject || !onDeleteProject) return;
    setIsDeleting(true);
    try {
      await onDeleteProject(currentProject.id);
      setShowDeleteConfirm(false);
    } catch {
    } finally {
      setIsDeleting(false);
    }
  };

  const tabs = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'attack-graph', label: 'Attack Graph' },
    { id: 'attack-paths', label: 'Attack Paths', count: counts?.attackPaths },
    { id: 'findings', label: 'Findings Matrix', count: counts?.findings },
    { id: 'remediation', label: 'Remediation Queue', count: counts?.remediations },
    { id: 'comparison', label: 'Scan Comparison' },
    { id: 'ingestion', label: 'Scan Ingestion' },
    { id: 'report', label: 'Security Report' },
  ];

  return (
    <header className="bg-slate-900/95 backdrop-blur-md border-b border-slate-800 sticky top-0 z-40 shadow-sm">
      {/* Top bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Title */}
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-950 to-slate-900 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-sm shadow-cyan-950">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-slate-100 tracking-tight text-base sm:text-lg">
                  AI Vulnerability Triage
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-800/80 uppercase">
                  Attack-Path Prioritizer
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Defensive Threat Modeling & High-Leverage Remediation Intelligence
              </p>
            </div>
          </div>

          {/* Project Switcher, Actions & Scope Badge */}
          <div className="flex items-center space-x-2.5">
            {/* Project Select Dropdown */}
            {projects.length > 0 && (
              <div className="relative flex items-center space-x-1.5 bg-slate-950/80 rounded-lg border border-slate-800 px-2.5 py-1.5">
                <FolderKanban className="w-4 h-4 text-cyan-400 shrink-0" />
                <select
                  id="project-selector"
                  value={currentProject?.id || ''}
                  onChange={(e) => {
                    const p = projects.find((proj) => proj.id === e.target.value);
                    if (p) onSelectProject(p);
                  }}
                  className="bg-transparent text-xs text-slate-200 focus:outline-none cursor-pointer pr-3 font-medium max-w-[160px] sm:max-w-[200px] truncate"
                >
                  {projects.map((p) => (
                    <option key={p.id} value={p.id} className="bg-slate-900 text-slate-200">
                      {p.name}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {/* Delete Project Button (if active project exists) */}
            {currentProject && onDeleteProject && (
              <button
                id="delete-project-btn"
                onClick={() => setShowDeleteConfirm(true)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-950/40 border border-transparent hover:border-rose-900/50 transition"
                title="Delete Current Project"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}

            {/* Reset Demo Button */}
            {/* New Project Button */}
            <button
              id="new-project-btn"
              onClick={onOpenNewProject}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition shadow-cyan-950/50"
              title="Create New Authorized Project"
            >
              <Plus className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">New Project</span>
            </button>

            {/* Audit Log Trigger */}
            <button
              id="audit-logs-btn"
              onClick={onOpenAuditLogs}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-slate-800/60 transition"
              title="View Audit Trail"
            >
              <FileCheck className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Navigation tabs */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 border-t border-slate-800/80">
        <nav className="flex space-x-1 sm:space-x-1.5 overflow-x-auto py-2 scrollbar-none text-xs sm:text-sm font-medium">
          {tabs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                id={`nav-tab-${tab.id}`}
                onClick={() => setActiveTab(tab.id)}
                className={`px-3 py-1.5 rounded-lg whitespace-nowrap transition flex items-center space-x-1.5 ${
                  isActive
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/90 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <span>{tab.label}</span>
                {typeof tab.count === 'number' && tab.count > 0 && (
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full font-bold ${
                      isActive
                        ? 'bg-cyan-900 text-cyan-200'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Delete Confirmation Modal */}
      {showDeleteConfirm && currentProject && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md p-6 space-y-4 shadow-2xl">
            <div className="flex items-center space-x-3 text-rose-400">
              <div className="w-10 h-10 rounded-xl bg-rose-950/80 border border-rose-800 flex items-center justify-center shrink-0">
                <AlertCircle className="w-5 h-5 text-rose-400" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-100">Delete Project?</h3>
                <p className="text-xs text-slate-400">This action cannot be undone.</p>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
              Are you sure you want to delete <strong className="text-slate-100">{currentProject.name}</strong> ({currentProject.targetScope}) and all of its associated scan findings and attack paths?
            </p>

            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setShowDeleteConfirm(false)}
                disabled={isDeleting}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold"
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                disabled={isDeleting}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-bold transition flex items-center space-x-1.5"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>{isDeleting ? 'Deleting...' : 'Confirm Delete'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </header>
  );
};

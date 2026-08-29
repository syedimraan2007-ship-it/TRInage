import React from 'react';
import { Project } from '../types';
import { Shield, ShieldAlert, Plus, FolderKanban, Terminal, FileCheck, Layers, BookOpen, AlertTriangle } from 'lucide-react';

interface HeaderProps {
  projects: Project[];
  currentProject: Project | null;
  onSelectProject: (p: Project) => void;
  onOpenNewProject: () => void;
  onOpenAuditLogs: () => void;
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export const Header: React.FC<HeaderProps> = ({
  projects,
  currentProject,
  onSelectProject,
  onOpenNewProject,
  onOpenAuditLogs,
  activeTab,
  setActiveTab,
}) => {
  return (
    <header className="bg-slate-900 border-b border-slate-800 sticky top-0 z-40">
      {/* Top bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Title */}
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-950 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-sm shadow-cyan-900/40">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-slate-100 tracking-tight text-base sm:text-lg">
                  AI Vulnerability Triage
                </span>
                <span className="text-xs px-2 py-0.5 rounded font-mono bg-cyan-950/80 text-cyan-300 border border-cyan-800">
                  ATTACK-PATH PRIORITIZER
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Defensive Threat Modeling & Remediation Intelligence
              </p>
            </div>
          </div>

          {/* Project Switcher & Scope Badge */}
          <div className="flex items-center space-x-3">
            {currentProject && (
              <div className="hidden lg:flex items-center space-x-2 bg-slate-950/70 px-3 py-1.5 rounded-md border border-slate-800 text-xs">
                <span className="text-slate-400">Authorized Scope:</span>
                <span className="font-mono text-emerald-400 font-medium truncate max-w-xs">
                  {currentProject.targetScope}
                </span>
              </div>
            )}

            {/* Project Select */}
            {projects.length > 0 && (
              <div className="relative flex items-center space-x-1.5 bg-slate-800/80 rounded-md border border-slate-700 px-2 py-1">
                <FolderKanban className="w-4 h-4 text-slate-400" />
                <select
                  id="project-selector"
                  value={currentProject?.id || ''}
                  onChange={(e) => {
                    const p = projects.find((proj) => proj.id === e.target.value);
                    if (p) onSelectProject(p);
                  }}
                  className="bg-transparent text-sm text-slate-200 focus:outline-none cursor-pointer pr-4 font-medium"
                >
                  {projects.map((p) => (
                    <option key={p.id} value={p.id} className="bg-slate-900 text-slate-200">
                      {p.name}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {/* New Project Button */}
            <button
              id="new-project-btn"
              onClick={onOpenNewProject}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition"
              title="Create New Authorized Project"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Project</span>
            </button>

            {/* Audit Log Trigger */}
            <button
              id="audit-logs-btn"
              onClick={onOpenAuditLogs}
              className="p-1.5 rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
              title="View Audit Trail"
            >
              <FileCheck className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Navigation tabs */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 border-t border-slate-800/80">
        <nav className="flex space-x-1 sm:space-x-2 overflow-x-auto py-2 scrollbar-none text-xs sm:text-sm font-medium">
          {[
            { id: 'dashboard', label: 'Dashboard' },
            { id: 'attack-graph', label: 'Attack Graph' },
            { id: 'attack-paths', label: 'Attack Paths' },
            { id: 'findings', label: 'Findings Matrix' },
            { id: 'remediation', label: 'Remediation Queue' },
            { id: 'comparison', label: 'Scan Comparison' },
            { id: 'ingestion', label: 'Scan Ingestion' },
            { id: 'report', label: 'Security Report' },
          ].map((tab) => (
            <button
              key={tab.id}
              id={`nav-tab-${tab.id}`}
              onClick={() => setActiveTab(tab.id)}
              className={`px-3 py-1.5 rounded-md whitespace-nowrap transition ${
                activeTab === tab.id
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>
    </header>
  );
};

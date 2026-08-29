import React, { useState, useEffect, useCallback } from 'react';
import { Project, Scan, NormalizedFinding, AttackPath, RemediationItem, ScanComparison, DashboardMetrics, FindingStatus } from './types';
import { api } from './api';
import { Header } from './components/Header';
import { LegalBanner } from './components/LegalBanner';
import { DashboardView } from './components/DashboardView';
import { AttackGraphView } from './components/AttackGraphView';
import { AttackPathsView } from './components/AttackPathsView';
import { FindingsView } from './components/FindingsView';
import { RemediationQueueView } from './components/RemediationQueueView';
import { ScanComparisonView } from './components/ScanComparisonView';
import { IngestionHubView } from './components/IngestionHubView';
import { ReportView } from './components/ReportView';
import { NewProjectModal } from './components/NewProjectModal';
import { AuditLogModal } from './components/AuditLogModal';
import { Activity, ShieldAlert } from 'lucide-react';

export function App() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [currentProject, setCurrentProject] = useState<Project | null>(null);
  const [activeTab, setActiveTab] = useState<string>('dashboard');

  // Active Project Data
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [findings, setFindings] = useState<NormalizedFinding[]>([]);
  const [remediations, setRemediations] = useState<RemediationItem[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [comparisons, setComparisons] = useState<ScanComparison[]>([]);
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);

  // Modals
  const [isNewProjectOpen, setIsNewProjectOpen] = useState(false);
  const [isAuditLogsOpen, setIsAuditLogsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Load projects on mount
  const loadProjects = useCallback(async () => {
    try {
      const projs = await api.getProjects();
      setProjects(projs);
      if (projs.length > 0 && !currentProject) {
        setCurrentProject(projs[0]);
      }
    } catch {
    } finally {
      setIsLoading(false);
    }
  }, [currentProject]);

  useEffect(() => {
    loadProjects();
  }, [loadProjects]);

  // Load project details whenever currentProject changes
  const loadProjectData = useCallback(async (projectId: string) => {
    try {
      const [dashMetrics, paths, allFindings, rems, allScans, comps] = await Promise.all([
        api.getDashboard(projectId),
        api.getAttackPaths(projectId),
        api.getFindings(projectId),
        api.getRemediations(projectId),
        api.getScans(projectId),
        api.getComparisons(projectId),
      ]);

      setMetrics(dashMetrics);
      setAttackPaths(paths);
      setFindings(allFindings);
      setRemediations(rems);
      setScans(allScans);
      setComparisons(comps);
    } catch {}
  }, []);

  useEffect(() => {
    if (currentProject) {
      loadProjectData(currentProject.id);
    }
  }, [currentProject, loadProjectData]);

  // Handlers
  const handleCreateProject = async (data: { name: string; targetScope: string; authorizedBy: string; description: string }) => {
    const newProj = await api.createProject(data);
    setProjects(prev => [newProj, ...prev]);
    setCurrentProject(newProj);
    return newProj;
  };

  const handleUploadScan = async (filename: string, rawContent: string) => {
    if (!currentProject) throw new Error('No active project');
    const result = await api.uploadScan(currentProject.id, filename, rawContent);
    await loadProjectData(currentProject.id);
    return result;
  };

  const handleProcessScan = async (scanId: string) => {
    if (!currentProject) throw new Error('No active project');
    const result = await api.processScan(currentProject.id, scanId);
    await loadProjectData(currentProject.id);
    return result;
  };

  const handleUpdateFindingStatus = async (findingId: string, status: FindingStatus) => {
    if (!currentProject) return;
    await api.updateFindingStatus(currentProject.id, findingId, status);
    setFindings(prev => prev.map(f => f.id === findingId ? { ...f, status } : f));
  };

  const handleUpdateRemediation = async (id: string, status: RemediationItem['status']) => {
    if (!currentProject) return;
    await api.updateRemediation(currentProject.id, id, { status });
    setRemediations(prev => prev.map(r => r.id === id ? { ...r, status } : r));
    await loadProjectData(currentProject.id);
  };

  const handleGenerateAiGuide = async (id: string) => {
    if (!currentProject) throw new Error('No active project');
    return api.getAiRemediationGuide(currentProject.id, id);
  };

  const handleCompareScans = async (scan1Id: string, scan2Id: string) => {
    if (!currentProject) throw new Error('No active project');
    const comp = await api.compareScans(currentProject.id, scan1Id, scan2Id);
    setComparisons(prev => [comp, ...prev.filter(c => c.id !== comp.id)]);
    return comp;
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-400 space-y-3">
        <Activity className="w-10 h-10 animate-spin text-cyan-400" />
        <p className="font-mono text-sm">Initializing defensive security intelligence platform...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-cyan-500 selection:text-black">
      {/* Top Header */}
      <Header
        projects={projects}
        currentProject={currentProject}
        onSelectProject={(p) => setCurrentProject(p)}
        onOpenNewProject={() => setIsNewProjectOpen(true)}
        onOpenAuditLogs={() => setIsAuditLogsOpen(true)}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
      />

      {/* Defensive Legal Scope Banner */}
      <LegalBanner
        authorizedScope={currentProject?.targetScope}
        authorizedBy={currentProject?.authorizedBy}
      />

      {/* Main View Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {!currentProject ? (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center text-slate-400 space-y-4 max-w-xl mx-auto my-12 shadow-xl">
            <div className="w-14 h-14 bg-cyan-950/60 border border-cyan-500/30 rounded-2xl flex items-center justify-center mx-auto text-cyan-400">
              <ShieldAlert className="w-7 h-7" />
            </div>
            <h2 className="text-xl font-bold text-slate-100">No Authorized Projects Configured</h2>
            <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
              Create an authorized project scope to begin ingesting vulnerability scanner logs, correlating multi-stage attack paths, and generating prioritized remediation plans.
            </p>
            <div className="pt-2">
              <button
                onClick={() => setIsNewProjectOpen(true)}
                className="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-bold transition shadow-md shadow-cyan-950/50"
              >
                Create New Project
              </button>
            </div>
          </div>
        ) : (
          <>
            {activeTab === 'dashboard' && (
              <DashboardView
                metrics={metrics}
                attackPaths={attackPaths}
                findings={findings}
                scans={scans}
                onNavigateTab={(tab) => setActiveTab(tab)}
                onSelectAttackPath={(pId) => {
                  setSelectedPathId(pId);
                  setActiveTab('attack-graph');
                }}
              />
            )}

            {activeTab === 'attack-graph' && (
              <AttackGraphView
                attackPaths={attackPaths}
                findings={findings}
                selectedPathId={selectedPathId}
                onSelectPathId={setSelectedPathId}
                onNavigateTab={(tab) => setActiveTab(tab)}
              />
            )}

            {activeTab === 'attack-paths' && (
              <AttackPathsView
                attackPaths={attackPaths}
                findings={findings}
                onSelectAttackPath={(pId) => {
                  setSelectedPathId(pId);
                  setActiveTab('attack-graph');
                }}
                onNavigateTab={(tab) => setActiveTab(tab)}
              />
            )}

            {activeTab === 'findings' && (
              <FindingsView
                findings={findings}
                onUpdateStatus={handleUpdateFindingStatus}
              />
            )}

            {activeTab === 'remediation' && (
              <RemediationQueueView
                remediations={remediations}
                projectId={currentProject.id}
                onUpdateStatus={handleUpdateRemediation}
                onGenerateAiGuide={handleGenerateAiGuide}
              />
            )}

            {activeTab === 'comparison' && (
              <ScanComparisonView
                scans={scans}
                comparisons={comparisons}
                onCompareScans={handleCompareScans}
              />
            )}

            {activeTab === 'ingestion' && (
              <IngestionHubView
                projectId={currentProject.id}
                onUploadScan={handleUploadScan}
                onProcessScan={handleProcessScan}
                onNavigateTab={(tab) => setActiveTab(tab)}
                scans={scans}
              />
            )}

            {activeTab === 'report' && (
              <ReportView projectId={currentProject.id} />
            )}
          </>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-4 text-center text-slate-600 text-xs font-mono">
        AI Vulnerability Triage & Attack-Path Prioritizer • Defensive Cybersecurity Intelligence & Threat Modeling
      </footer>

      {/* Modals */}
      <NewProjectModal
        isOpen={isNewProjectOpen}
        onClose={() => setIsNewProjectOpen(false)}
        onCreateProject={handleCreateProject}
      />

      <AuditLogModal
        isOpen={isAuditLogsOpen}
        onClose={() => setIsAuditLogsOpen(false)}
        projectId={currentProject?.id}
      />
    </div>
  );
}

export default App;

import React, { useState, useEffect, useCallback, useRef } from 'react';
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
import { ChatCopilotView } from './components/ChatCopilotView';
import { NewProjectModal } from './components/NewProjectModal';
import { AuditLogModal } from './components/AuditLogModal';
import { Activity, ShieldAlert, FolderPlus, Bot, Sparkles } from 'lucide-react';

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

  // Modals & UI State
  const [isNewProjectOpen, setIsNewProjectOpen] = useState(false);
  const [isAuditLogsOpen, setIsAuditLogsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Prevent race conditions and double loads
  const loadingProjectIdRef = useRef<string | null>(null);

  // Load project details whenever currentProject changes
  const loadProjectData = useCallback(async (projectId: string) => {
    if (!projectId || loadingProjectIdRef.current === projectId) return;
    loadingProjectIdRef.current = projectId;

    try {
      const [dashMetrics, paths, allFindings, rems, allScans, comps] = await Promise.all([
        api.getDashboard(projectId).catch(() => null),
        api.getAttackPaths(projectId).catch(() => []),
        api.getFindings(projectId).catch(() => []),
        api.getRemediations(projectId).catch(() => []),
        api.getScans(projectId).catch(() => []),
        api.getComparisons(projectId).catch(() => []),
      ]);

      setMetrics(dashMetrics);
      setAttackPaths(paths || []);
      setFindings(allFindings || []);
      setRemediations(rems || []);
      setScans(allScans || []);
      setComparisons(comps || []);
    } catch (err) {
      console.error('Error loading project data:', err);
    } finally {
      loadingProjectIdRef.current = null;
    }
  }, []);

  // Initial load on mount
  useEffect(() => {
    let mounted = true;

    async function init() {
      try {
        const projs = await api.getProjects();
        if (!mounted) return;
        setProjects(projs);
        if (projs && projs.length > 0) {
          const savedActiveId = api.getActiveProjectId();
          const target = (savedActiveId && projs.find(p => p.id === savedActiveId)) || projs[0];
          setCurrentProject(target);
          api.setActiveProjectId(target.id);
        } else {
          setCurrentProject(null);
          setIsNewProjectOpen(true);
        }
      } catch (err) {
        console.error('Failed to load initial projects:', err);
      } finally {
        if (mounted) setIsLoading(false);
      }
    }

    init();

    return () => {
      mounted = false;
    };
  }, []);

  // Sync data when currentProject id changes
  useEffect(() => {
    if (currentProject?.id) {
      loadProjectData(currentProject.id);
    } else {
      setMetrics(null);
      setAttackPaths([]);
      setFindings([]);
      setRemediations([]);
      setScans([]);
      setComparisons([]);
    }
  }, [currentProject?.id, loadProjectData]);

  // Handlers
  const handleCreateProject = async (data: { name: string; targetScope: string; authorizedBy: string; description: string }) => {
    const newProj = await api.createProject(data);
    setProjects(prev => [newProj, ...prev]);
    setCurrentProject(newProj);
    setActiveTab('ingestion');
    return newProj;
  };

  const handleDeleteProject = async (projectId: string) => {
    await api.deleteProject(projectId);
    const remaining = projects.filter(p => p.id !== projectId);
    setProjects(remaining);
    if (remaining.length > 0) {
      setCurrentProject(remaining[0]);
    } else {
      setCurrentProject(null);
      setIsNewProjectOpen(true);
    }
  };

  const handleUploadScan = async (filename: string, rawContent: string) => {
    if (!currentProject) throw new Error('No active project');
    const result = await api.uploadScan(currentProject.id, filename, rawContent);
    
    if (result.findings && result.findings.length > 0) setFindings(result.findings);
    if (result.attackPaths && result.attackPaths.length > 0) setAttackPaths(result.attackPaths);
    if (result.remediations && result.remediations.length > 0) setRemediations(result.remediations);
    if (result.scan) setScans(prev => [result.scan, ...prev.filter(s => s.id !== result.scan.id)]);
    if (result.metrics) setMetrics(result.metrics);

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
    await loadProjectData(currentProject.id);
  };

  const handleUpdateRemediation = async (id: string, status: RemediationItem['status']) => {
    if (!currentProject) return;
    await api.updateRemediation(currentProject.id, id, { status });
    setRemediations(prev => prev.map(r => r.id === id ? { ...r, status } : r));
    await loadProjectData(currentProject.id);
  };

  const handleGenerateAiGuide = async (id: string) => {
    if (!currentProject) throw new Error('No active project');
    const guidance = await api.getAiRemediationGuide(currentProject.id, id);
    setRemediations(prev => prev.map(r => r.id === id ? { ...r, aiGuidance: guidance } : r));
    return guidance;
  };

  const handleCompareScans = async (scan1Id: string, scan2Id: string) => {
    if (!currentProject) throw new Error('No active project');
    const comp = await api.compareScans(currentProject.id, scan1Id, scan2Id);
    setComparisons(prev => [comp, ...prev.filter(c => c.id !== comp.id)]);
    await loadProjectData(currentProject.id);
    return comp;
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center space-y-4 text-cyan-400">
        <Activity className="w-8 h-8 animate-pulse text-cyan-400" />
        <span className="text-xs tracking-widest font-mono text-slate-400 uppercase">
          Initializing Defensive Security Platform...
        </span>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/20 selection:text-cyan-200">
      {/* Platform Header */}
      <Header
        projects={projects}
        currentProject={currentProject}
        onSelectProject={(p) => {
          setCurrentProject(p);
          api.setActiveProjectId(p.id);
        }}
        onOpenNewProject={() => setIsNewProjectOpen(true)}
        onOpenAuditLogs={() => setIsAuditLogsOpen(true)}
        onDeleteProject={handleDeleteProject}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        counts={{
          findings: findings.length,
          attackPaths: attackPaths.length,
          remediations: remediations.filter(r => r.status !== 'verified_fixed').length,
        }}
      />

      {/* Defensive Legal Scope Banner */}
      <LegalBanner
        authorizedScope={currentProject?.targetScope}
        authorizedBy={currentProject?.authorizedBy}
      />

      {/* Main View Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {!currentProject ? (
          <div className="cyber-card border border-slate-800 rounded-3xl p-12 text-center text-slate-400 space-y-5 max-w-xl mx-auto my-12 shadow-2xl">
            <div className="w-14 h-14 bg-cyan-950/80 border border-cyan-500/40 rounded-2xl flex items-center justify-center mx-auto text-cyan-400 shadow-md">
              <ShieldAlert className="w-7 h-7" />
            </div>
            <div className="space-y-1">
              <h2 className="text-xl font-bold text-slate-100">No Authorized Projects Configured</h2>
              <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
                Define an authorized defensive target scope to begin ingesting security scan reports and prioritizing attack paths.
              </p>
            </div>

            <div className="pt-2 flex items-center justify-center">
              <button
                onClick={() => setIsNewProjectOpen(true)}
                className="px-6 py-3 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-bold transition shadow-lg shadow-cyan-950/60 flex items-center justify-center space-x-2"
              >
                <FolderPlus className="w-4 h-4" />
                <span>Create New Project</span>
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
                onSelectPathId={(pId) => {
                  setSelectedPathId(pId);
                  setActiveTab('attack-graph');
                }}
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
                findings={findings}
                attackPaths={attackPaths}
                projectId={currentProject.id}
                onUpdateStatus={handleUpdateRemediation}
                onGenerateAiGuide={handleGenerateAiGuide}
              />
            )}

            {activeTab === 'chat' && (
              <ChatCopilotView
                currentProject={currentProject}
                findings={findings}
                attackPaths={attackPaths}
                onNavigateTab={(tab) => setActiveTab(tab)}
              />
            )}

            {activeTab === 'comparison' && (
              <ScanComparisonView
                scans={scans}
                comparisons={comparisons}
                projectId={currentProject.id}
                onCompareScans={handleCompareScans}
                onScanCompared={() => loadProjectData(currentProject.id)}
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
              <ReportView
                projectId={currentProject.id}
              />
            )}
          </>
        )}
      </main>

      {/* Floating AI Copilot Quick Launcher */}
      {currentProject && activeTab !== 'chat' && (
        <button
          id="floating-chat-launcher"
          onClick={() => setActiveTab('chat')}
          className="fixed bottom-6 right-6 z-40 px-4 py-3 bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white rounded-2xl shadow-xl shadow-cyan-950/80 border border-cyan-400/40 flex items-center space-x-2.5 transition group hover:scale-105"
          title="Open Gemini Defensive Copilot"
        >
          <div className="relative">
            <Bot className="w-5 h-5 text-white" />
            <Sparkles className="w-2.5 h-2.5 text-yellow-300 absolute -top-1 -right-1 animate-pulse" />
          </div>
          <span className="text-xs font-bold font-sans">AI Copilot</span>
        </button>
      )}

      {/* New Project Scope Modal */}
      <NewProjectModal
        isOpen={isNewProjectOpen}
        onClose={() => setIsNewProjectOpen(false)}
        onCreateProject={handleCreateProject}
      />

      {/* Audit Log Modal */}
      <AuditLogModal
        isOpen={isAuditLogsOpen}
        onClose={() => setIsAuditLogsOpen(false)}
        projectId={currentProject?.id}
      />
    </div>
  );
}

export default App;

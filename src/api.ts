import {
  Project,
  Scan,
  NormalizedFinding,
  AttackPath,
  RemediationItem,
  ScanComparison,
  DashboardMetrics,
  AssessmentReport,
} from './types';

const STORAGE_KEYS = {
  PROJECTS: 'AI_VULN_PROJECTS_V1',
  ACTIVE_PROJECT: 'AI_VULN_ACTIVE_PROJECT_ID_V1',
  PROJECT_DATA_PREFIX: 'AI_VULN_PROJECT_DATA_V1_',
};

interface ProjectStore {
  scans: Scan[];
  findings: NormalizedFinding[];
  attackPaths: AttackPath[];
  remediations: RemediationItem[];
  comparisons: ScanComparison[];
  auditLogs: any[];
}

function getLocalProjects(): Project[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.PROJECTS);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveLocalProjects(projects: Project[]) {
  try {
    localStorage.setItem(STORAGE_KEYS.PROJECTS, JSON.stringify(projects));
  } catch {}
}

function getLocalProjectData(projectId: string): ProjectStore {
  try {
    const raw = localStorage.getItem(`${STORAGE_KEYS.PROJECT_DATA_PREFIX}${projectId}`);
    if (raw) return JSON.parse(raw);
  } catch {}
  return {
    scans: [],
    findings: [],
    attackPaths: [],
    remediations: [],
    comparisons: [],
    auditLogs: [],
  };
}

function saveLocalProjectData(projectId: string, updates: Partial<ProjectStore>) {
  try {
    const current = getLocalProjectData(projectId);
    const updated = { ...current, ...updates };
    localStorage.setItem(`${STORAGE_KEYS.PROJECT_DATA_PREFIX}${projectId}`, JSON.stringify(updated));
  } catch {}
}

async function handleResponse<T>(res: Response, defaultErrorMsg: string): Promise<T> {
  if (!res.ok) {
    let errorMessage = defaultErrorMsg;
    try {
      const err = await res.json();
      errorMessage = err.error || err.message || defaultErrorMsg;
    } catch {
      try {
        const text = await res.text();
        if (text && text.length < 200) errorMessage = text;
      } catch {}
    }
    throw new Error(errorMessage);
  }
  return res.json();
}

export const api = {
  // Storage helpers for App
  getActiveProjectId(): string | null {
    try {
      return localStorage.getItem(STORAGE_KEYS.ACTIVE_PROJECT);
    } catch {
      return null;
    }
  },

  setActiveProjectId(id: string | null) {
    try {
      if (id) {
        localStorage.setItem(STORAGE_KEYS.ACTIVE_PROJECT, id);
      } else {
        localStorage.removeItem(STORAGE_KEYS.ACTIVE_PROJECT);
      }
    } catch {}
  },

  // Projects
  async getProjects(): Promise<Project[]> {
    const local = getLocalProjects();
    try {
      const res = await fetch('/api/projects');
      const remote = await handleResponse<Project[]>(res, 'Failed to fetch projects');
      if (remote && remote.length > 0) {
        // Merge with local
        const map = new Map<string, Project>();
        local.forEach(p => map.set(p.id, p));
        remote.forEach(p => map.set(p.id, p));
        const merged = Array.from(map.values());
        saveLocalProjects(merged);
        return merged;
      } else if (local.length > 0) {
        // Serverless container cold boot: re-sync local projects to server in background
        local.forEach(p => {
          fetch('/api/projects', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              name: p.name,
              targetScope: p.targetScope,
              authorizedBy: p.authorizedBy,
              description: p.description,
            }),
          }).catch(() => {});
        });
        return local;
      }
      return remote || [];
    } catch {
      return local;
    }
  },

  async getProject(id: string): Promise<Project> {
    try {
      const res = await fetch(`/api/projects/${id}`);
      const proj = await handleResponse<Project>(res, 'Failed to fetch project');
      return proj;
    } catch {
      const local = getLocalProjects().find(p => p.id === id);
      if (local) return local;
      throw new Error('Project not found.');
    }
  },

  async createProject(data: { name: string; targetScope: string; authorizedBy: string; description: string }): Promise<Project> {
    try {
      const res = await fetch('/api/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      const proj = await handleResponse<Project>(res, 'Failed to create project');
      const local = getLocalProjects();
      saveLocalProjects([proj, ...local.filter(p => p.id !== proj.id)]);
      api.setActiveProjectId(proj.id);
      return proj;
    } catch {
      const fallbackProj: Project = {
        id: `PRJ-${Date.now().toString(36).toUpperCase()}`,
        name: data.name,
        targetScope: data.targetScope,
        authorizedBy: data.authorizedBy,
        description: data.description,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      const local = getLocalProjects();
      saveLocalProjects([fallbackProj, ...local]);
      api.setActiveProjectId(fallbackProj.id);
      return fallbackProj;
    }
  },

  async deleteProject(id: string): Promise<void> {
    const local = getLocalProjects().filter(p => p.id !== id);
    saveLocalProjects(local);
    try {
      localStorage.removeItem(`${STORAGE_KEYS.PROJECT_DATA_PREFIX}${id}`);
    } catch {}
    try {
      await fetch(`/api/projects/${id}`, { method: 'DELETE' });
    } catch {}
  },

  // Scans
  async getScans(projectId: string): Promise<Scan[]> {
    try {
      const res = await fetch(`/api/projects/${projectId}/scans`);
      const scans = await handleResponse<Scan[]>(res, 'Failed to fetch scans');
      if (scans && scans.length > 0) {
        saveLocalProjectData(projectId, { scans });
        return scans;
      }
    } catch {}
    return getLocalProjectData(projectId).scans;
  },

  async uploadScan(projectId: string, filename: string, rawContent: string): Promise<any> {
    const res = await fetch(`/api/projects/${projectId}/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename, rawContent }),
    });
    const result = await handleResponse<any>(res, 'Failed to upload scan');
    
    // Save to local cache
    const current = getLocalProjectData(projectId);
    const newScans = [result.scan, ...current.scans.filter(s => s.id !== result.scan.id)];
    const newFindings = result.findings || result.deduplication?.canonicalFindings || current.findings;
    const newAttackPaths = result.attackPaths || current.attackPaths;
    const newRemediations = result.remediations || current.remediations;
    saveLocalProjectData(projectId, {
      scans: newScans,
      findings: newFindings,
      attackPaths: newAttackPaths,
      remediations: newRemediations,
    });

    return result;
  },

  async processScan(projectId: string, scanId: string): Promise<{ success: boolean; findingsCount: number; attackPathsCount: number; remediationsCount: number }> {
    try {
      const res = await fetch(`/api/projects/${projectId}/scans/${scanId}/process`, {
        method: 'POST',
      });
      return await handleResponse<{ success: boolean; findingsCount: number; attackPathsCount: number; remediationsCount: number }>(res, 'Failed to process scan');
    } catch {
      return { success: true, findingsCount: 0, attackPathsCount: 0, remediationsCount: 0 };
    }
  },

  // Findings
  async getFindings(projectId: string, filters?: { scanId?: string; severity?: string; asset?: string; status?: string; search?: string }): Promise<NormalizedFinding[]> {
    const local = getLocalProjectData(projectId).findings;
    try {
      const params = new URLSearchParams();
      if (filters?.scanId) params.append('scanId', filters.scanId);
      if (filters?.severity) params.append('severity', filters.severity);
      if (filters?.asset) params.append('asset', filters.asset);
      if (filters?.status) params.append('status', filters.status);
      if (filters?.search) params.append('search', filters.search);

      const res = await fetch(`/api/projects/${projectId}/findings?${params.toString()}`);
      const findings = await handleResponse<NormalizedFinding[]>(res, 'Failed to fetch findings');
      if (findings && findings.length > 0) {
        saveLocalProjectData(projectId, { findings });
        return findings;
      }
    } catch {}
    return local;
  },

  async updateFindingStatus(projectId: string, findingId: string, status: string): Promise<NormalizedFinding> {
    const current = getLocalProjectData(projectId);
    const updatedFindings = current.findings.map(f => f.id === findingId ? { ...f, status: status as any } : f);
    saveLocalProjectData(projectId, { findings: updatedFindings });

    try {
      const res = await fetch(`/api/projects/${projectId}/findings/${findingId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });
      return await handleResponse<NormalizedFinding>(res, 'Failed to update finding status');
    } catch {
      return updatedFindings.find(f => f.id === findingId)!;
    }
  },

  // Attack Paths
  async getAttackPaths(projectId: string, scanId?: string): Promise<AttackPath[]> {
    const local = getLocalProjectData(projectId).attackPaths;
    try {
      const url = scanId ? `/api/projects/${projectId}/attack-paths?scanId=${scanId}` : `/api/projects/${projectId}/attack-paths`;
      const res = await fetch(url);
      const paths = await handleResponse<AttackPath[]>(res, 'Failed to fetch attack paths');
      if (paths && paths.length > 0) {
        saveLocalProjectData(projectId, { attackPaths: paths });
        return paths;
      }
    } catch {}
    return local;
  },

  // Remediations
  async getRemediations(projectId: string): Promise<RemediationItem[]> {
    const local = getLocalProjectData(projectId).remediations;
    try {
      const res = await fetch(`/api/projects/${projectId}/remediations`);
      const rems = await handleResponse<RemediationItem[]>(res, 'Failed to fetch remediations');
      if (rems && rems.length > 0) {
        saveLocalProjectData(projectId, { remediations: rems });
        return rems;
      }
    } catch {}
    return local;
  },

  async updateRemediation(projectId: string, id: string, updates: Partial<RemediationItem>): Promise<RemediationItem> {
    const current = getLocalProjectData(projectId);
    const updatedRems = current.remediations.map(r => r.id === id ? { ...r, ...updates } : r);
    saveLocalProjectData(projectId, { remediations: updatedRems });

    try {
      const res = await fetch(`/api/projects/${projectId}/remediations/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      });
      return await handleResponse<RemediationItem>(res, 'Failed to update remediation');
    } catch {
      return updatedRems.find(r => r.id === id)!;
    }
  },

  async getAiRemediationGuide(projectId: string, id: string): Promise<RemediationItem['aiGuidance']> {
    const res = await fetch(`/api/projects/${projectId}/remediations/${id}/ai-guide`, {
      method: 'POST',
    });
    return handleResponse<RemediationItem['aiGuidance']>(res, 'Failed to generate AI remediation guide');
  },

  // Scan Comparison
  async compareScans(projectId: string, scan1Id: string, scan2Id: string): Promise<ScanComparison> {
    const res = await fetch(`/api/projects/${projectId}/compare`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan1Id, scan2Id }),
    });
    const comp = await handleResponse<ScanComparison>(res, 'Failed to compare scans');
    const current = getLocalProjectData(projectId);
    saveLocalProjectData(projectId, { comparisons: [comp, ...current.comparisons] });
    return comp;
  },

  async getComparisons(projectId: string): Promise<ScanComparison[]> {
    try {
      const res = await fetch(`/api/projects/${projectId}/comparisons`);
      const comps = await handleResponse<ScanComparison[]>(res, 'Failed to fetch comparisons');
      if (comps && comps.length > 0) {
        saveLocalProjectData(projectId, { comparisons: comps });
        return comps;
      }
    } catch {}
    return getLocalProjectData(projectId).comparisons;
  },

  // Dashboard & Reports
  async getDashboard(projectId: string): Promise<DashboardMetrics> {
    try {
      const res = await fetch(`/api/projects/${projectId}/dashboard`);
      return await handleResponse<DashboardMetrics>(res, 'Failed to fetch dashboard metrics');
    } catch {
      const data = getLocalProjectData(projectId);
      const total = data.findings.length;
      const crit = data.findings.filter(f => f.severity === 'Critical').length;
      const high = data.findings.filter(f => f.severity === 'High').length;
      const med = data.findings.filter(f => f.severity === 'Medium').length;
      const low = data.findings.filter(f => f.severity === 'Low').length;
      const info = data.findings.filter(f => f.severity === 'Info').length;
      const verified = data.remediations.filter(r => r.status === 'verified_fixed').length;
      const unverified = data.remediations.filter(r => r.status !== 'verified_fixed').length;
      const assets = Array.from(new Set(data.findings.map(f => f.asset)));

      return {
        totalFindings: total,
        uniqueFindings: total,
        criticalFindings: crit,
        highFindings: high,
        mediumFindings: med,
        lowFindings: low,
        infoFindings: info,
        activeAttackPaths: data.attackPaths.length,
        criticalAttackPaths: data.attackPaths.filter(p => p.severity === 'Critical').length,
        affectedAssets: assets,
        unresolvedRemediations: unverified,
        resolvedRemediations: verified,
        postureRating: crit > 0 ? 'CRITICAL RISK' : high > 0 ? 'ELEVATED RISK' : total > 0 ? 'MODERATE RISK' : 'SECURE POSTURE',
        averageContextualRisk: data.attackPaths.length > 0 ? Math.round(data.attackPaths.reduce((a, b) => a + b.contextualScore, 0) / data.attackPaths.length) : 0,
      };
    }
  },

  async getReport(projectId: string): Promise<AssessmentReport> {
    try {
      const res = await fetch(`/api/projects/${projectId}/report`);
      const report = await handleResponse<AssessmentReport>(res, 'Failed to fetch assessment report');
      if (report && report.project) return report;
    } catch {}

    const project = getLocalProjects().find(p => p.id === projectId) || {
      id: projectId,
      name: 'Defensive Security Scope',
      targetScope: '*.enterprise.internal',
      authorizedBy: 'Lead SecOps Officer',
      description: 'Authorized security target',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    const data = getLocalProjectData(projectId);
    const metrics = await api.getDashboard(projectId);
    const latestScan = data.scans[0] || {
      id: 'SCN-LOCAL',
      projectId,
      filename: 'Consolidated Security Assessment',
      scannerType: 'generic_json' as any,
      uploadedAt: new Date().toISOString(),
      totalRawFindings: data.findings.length,
      deduplicatedCount: data.findings.length,
      status: 'completed' as any,
      statusMessage: 'Ready',
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    };

    return {
      project,
      scan: latestScan,
      metrics,
      topAttackPaths: data.attackPaths.slice(0, 10),
      prioritizedRemediations: data.remediations,
      highRiskAssets: Array.from(new Set(data.findings.map(f => f.asset))).map(asset => ({
        asset,
        findingCount: data.findings.filter(f => f.asset === asset).length,
        maxSeverity: (data.findings.find(f => f.asset === asset)?.severity || 'Low') as any,
        criticalPathsCount: data.attackPaths.filter(p => (p.participatingAssets || []).includes(asset)).length,
      })),
      methodology: 'Normalized heterogeneous scanner ingestion, deterministic deduplication clustering, context-calibrated AI triage, graph-based attack path modeling, and deterministic mathematical risk prioritization.',
      aiLimitations: 'All AI conclusions are strictly derived from supplied scanner evidence. No unauthorized exploitation was performed. Testing is restricted to explicitly authorized assets.',
      generatedAt: new Date().toISOString(),
    };
  },

  // Samples
  async getSamples(): Promise<any[]> {
    const res = await fetch('/api/samples');
    return handleResponse<any[]>(res, 'Failed to fetch sample datasets');
  },

  async loadSample(sampleId: string, projectId?: string): Promise<any> {
    const res = await fetch('/api/load-sample', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sampleId, projectId }),
    });
    const result = await handleResponse<any>(res, 'Failed to load sample dataset');
    if (projectId && result.scan) {
      const current = getLocalProjectData(projectId);
      const newScans = [result.scan, ...current.scans.filter(s => s.id !== result.scan.id)];
      const newFindings = result.findings || result.deduplication?.canonicalFindings || current.findings;
      const newAttackPaths = result.attackPaths || current.attackPaths;
      const newRemediations = result.remediations || current.remediations;
      saveLocalProjectData(projectId, {
        scans: newScans,
        findings: newFindings,
        attackPaths: newAttackPaths,
        remediations: newRemediations,
      });
    }
    return result;
  },

  // Audit Logs
  async getAuditLogs(projectId?: string): Promise<any[]> {
    try {
      const url = projectId ? `/api/audit-logs?projectId=${projectId}` : '/api/audit-logs';
      const res = await fetch(url);
      return await handleResponse<any[]>(res, 'Failed to fetch audit logs');
    } catch {
      return [];
    }
  },
};

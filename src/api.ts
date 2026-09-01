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
  // Projects
  async getProjects(): Promise<Project[]> {
    const res = await fetch('/api/projects');
    return handleResponse<Project[]>(res, 'Failed to fetch projects');
  },

  async getProject(id: string): Promise<Project> {
    const res = await fetch(`/api/projects/${id}`);
    return handleResponse<Project>(res, 'Failed to fetch project');
  },

  async createProject(data: { name: string; targetScope: string; authorizedBy: string; description: string }): Promise<Project> {
    const res = await fetch('/api/projects', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return handleResponse<Project>(res, 'Failed to create project');
  },

  async deleteProject(id: string): Promise<void> {
    const res = await fetch(`/api/projects/${id}`, {
      method: 'DELETE',
    });
    return handleResponse<void>(res, 'Failed to delete project');
  },

  async resetDemo(): Promise<Project> {
    const res = await fetch('/api/projects/reset-demo', {
      method: 'POST',
    });
    const data = await handleResponse<{ success: boolean; project: Project }>(res, 'Failed to reset demo');
    return data.project;
  },

  // Scans
  async getScans(projectId: string): Promise<Scan[]> {
    const res = await fetch(`/api/projects/${projectId}/scans`);
    return handleResponse<Scan[]>(res, 'Failed to fetch scans');
  },

  async uploadScan(projectId: string, filename: string, rawContent: string): Promise<{ scan: Scan; deduplication: any }> {
    const res = await fetch(`/api/projects/${projectId}/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename, rawContent }),
    });
    return handleResponse<{ scan: Scan; deduplication: any }>(res, 'Failed to upload scan');
  },

  async processScan(projectId: string, scanId: string): Promise<{ success: boolean; findingsCount: number; attackPathsCount: number; remediationsCount: number }> {
    const res = await fetch(`/api/projects/${projectId}/scans/${scanId}/process`, {
      method: 'POST',
    });
    return handleResponse<{ success: boolean; findingsCount: number; attackPathsCount: number; remediationsCount: number }>(res, 'Failed to process scan pipeline');
  },

  // Findings
  async getFindings(projectId: string, filters?: { scanId?: string; severity?: string; asset?: string; status?: string; search?: string }): Promise<NormalizedFinding[]> {
    const params = new URLSearchParams();
    if (filters?.scanId) params.append('scanId', filters.scanId);
    if (filters?.severity) params.append('severity', filters.severity);
    if (filters?.asset) params.append('asset', filters.asset);
    if (filters?.status) params.append('status', filters.status);
    if (filters?.search) params.append('search', filters.search);

    const res = await fetch(`/api/projects/${projectId}/findings?${params.toString()}`);
    return handleResponse<NormalizedFinding[]>(res, 'Failed to fetch findings');
  },

  async updateFindingStatus(projectId: string, findingId: string, status: string): Promise<NormalizedFinding> {
    const res = await fetch(`/api/projects/${projectId}/findings/${findingId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    return handleResponse<NormalizedFinding>(res, 'Failed to update finding status');
  },

  // Attack Paths
  async getAttackPaths(projectId: string, scanId?: string): Promise<AttackPath[]> {
    const url = scanId ? `/api/projects/${projectId}/attack-paths?scanId=${scanId}` : `/api/projects/${projectId}/attack-paths`;
    const res = await fetch(url);
    return handleResponse<AttackPath[]>(res, 'Failed to fetch attack paths');
  },

  // Remediations
  async getRemediations(projectId: string): Promise<RemediationItem[]> {
    const res = await fetch(`/api/projects/${projectId}/remediations`);
    return handleResponse<RemediationItem[]>(res, 'Failed to fetch remediations');
  },

  async updateRemediation(projectId: string, id: string, updates: Partial<RemediationItem>): Promise<RemediationItem> {
    const res = await fetch(`/api/projects/${projectId}/remediations/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    return handleResponse<RemediationItem>(res, 'Failed to update remediation');
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
    return handleResponse<ScanComparison>(res, 'Failed to compare scans');
  },

  async getComparisons(projectId: string): Promise<ScanComparison[]> {
    const res = await fetch(`/api/projects/${projectId}/comparisons`);
    return handleResponse<ScanComparison[]>(res, 'Failed to fetch comparisons');
  },

  // Dashboard & Reports
  async getDashboard(projectId: string): Promise<DashboardMetrics> {
    const res = await fetch(`/api/projects/${projectId}/dashboard`);
    return handleResponse<DashboardMetrics>(res, 'Failed to fetch dashboard metrics');
  },

  async getReport(projectId: string): Promise<AssessmentReport> {
    const res = await fetch(`/api/projects/${projectId}/report`);
    return handleResponse<AssessmentReport>(res, 'Failed to fetch assessment report');
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
    return handleResponse<any>(res, 'Failed to load sample dataset');
  },

  // Audit Logs
  async getAuditLogs(projectId?: string): Promise<any[]> {
    const url = projectId ? `/api/audit-logs?projectId=${projectId}` : '/api/audit-logs';
    const res = await fetch(url);
    return handleResponse<any[]>(res, 'Failed to fetch audit logs');
  },
};

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

export const api = {
  // Projects
  async getProjects(): Promise<Project[]> {
    const res = await fetch('/api/projects');
    if (!res.ok) throw new Error('Failed to fetch projects');
    return res.json();
  },

  async getProject(id: string): Promise<Project> {
    const res = await fetch(`/api/projects/${id}`);
    if (!res.ok) throw new Error('Failed to fetch project');
    return res.json();
  },

  async createProject(data: { name: string; targetScope: string; authorizedBy: string; description: string }): Promise<Project> {
    const res = await fetch('/api/projects', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to create project');
    }
    return res.json();
  },

  async deleteProject(id: string): Promise<void> {
    const res = await fetch(`/api/projects/${id}`, {
      method: 'DELETE',
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to delete project');
    }
  },

  async resetDemo(): Promise<Project> {
    const res = await fetch('/api/projects/reset-demo', {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to reset demo');
    }
    const data = await res.json();
    return data.project;
  },

  // Scans
  async getScans(projectId: string): Promise<Scan[]> {
    const res = await fetch(`/api/projects/${projectId}/scans`);
    if (!res.ok) throw new Error('Failed to fetch scans');
    return res.json();
  },

  async uploadScan(projectId: string, filename: string, rawContent: string): Promise<{ scan: Scan; deduplication: any }> {
    const res = await fetch(`/api/projects/${projectId}/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename, rawContent }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to upload scan');
    }
    return res.json();
  },

  async processScan(projectId: string, scanId: string): Promise<{ success: boolean; findingsCount: number; attackPathsCount: number; remediationsCount: number }> {
    const res = await fetch(`/api/projects/${projectId}/scans/${scanId}/process`, {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to process scan pipeline');
    }
    return res.json();
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
    if (!res.ok) throw new Error('Failed to fetch findings');
    return res.json();
  },

  async updateFindingStatus(projectId: string, findingId: string, status: string): Promise<NormalizedFinding> {
    const res = await fetch(`/api/projects/${projectId}/findings/${findingId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    if (!res.ok) throw new Error('Failed to update finding status');
    return res.json();
  },

  // Attack Paths
  async getAttackPaths(projectId: string, scanId?: string): Promise<AttackPath[]> {
    const url = scanId ? `/api/projects/${projectId}/attack-paths?scanId=${scanId}` : `/api/projects/${projectId}/attack-paths`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch attack paths');
    return res.json();
  },

  // Remediations
  async getRemediations(projectId: string): Promise<RemediationItem[]> {
    const res = await fetch(`/api/projects/${projectId}/remediations`);
    if (!res.ok) throw new Error('Failed to fetch remediations');
    return res.json();
  },

  async updateRemediation(projectId: string, id: string, updates: Partial<RemediationItem>): Promise<RemediationItem> {
    const res = await fetch(`/api/projects/${projectId}/remediations/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    if (!res.ok) throw new Error('Failed to update remediation');
    return res.json();
  },

  async getAiRemediationGuide(projectId: string, id: string): Promise<RemediationItem['aiGuidance']> {
    const res = await fetch(`/api/projects/${projectId}/remediations/${id}/ai-guide`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error('Failed to generate AI remediation guide');
    return res.json();
  },

  // Scan Comparison
  async compareScans(projectId: string, scan1Id: string, scan2Id: string): Promise<ScanComparison> {
    const res = await fetch(`/api/projects/${projectId}/compare`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan1Id, scan2Id }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to compare scans');
    }
    return res.json();
  },

  async getComparisons(projectId: string): Promise<ScanComparison[]> {
    const res = await fetch(`/api/projects/${projectId}/comparisons`);
    if (!res.ok) throw new Error('Failed to fetch comparisons');
    return res.json();
  },

  // Dashboard & Reports
  async getDashboard(projectId: string): Promise<DashboardMetrics> {
    const res = await fetch(`/api/projects/${projectId}/dashboard`);
    if (!res.ok) throw new Error('Failed to fetch dashboard metrics');
    return res.json();
  },

  async getReport(projectId: string): Promise<AssessmentReport> {
    const res = await fetch(`/api/projects/${projectId}/report`);
    if (!res.ok) throw new Error('Failed to fetch assessment report');
    return res.json();
  },

  // Samples
  async getSamples(): Promise<any[]> {
    const res = await fetch('/api/samples');
    if (!res.ok) throw new Error('Failed to fetch sample datasets');
    return res.json();
  },

  async loadSample(sampleId: string, projectId?: string): Promise<any> {
    const res = await fetch('/api/load-sample', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sampleId, projectId }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to load sample dataset');
    }
    return res.json();
  },

  // Audit Logs
  async getAuditLogs(projectId?: string): Promise<any[]> {
    const url = projectId ? `/api/audit-logs?projectId=${projectId}` : '/api/audit-logs';
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch audit logs');
    return res.json();
  },
};

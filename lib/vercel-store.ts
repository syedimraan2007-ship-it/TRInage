import { SAMPLE_PROJECT, SAMPLE_FINDINGS, SAMPLE_ATTACK_PATHS, SAMPLE_REMEDIATIONS } from '../server/sampleData';

declare global {
  var __ai_vuln_store__: any;
}

function ensureStore() {
  if (!globalThis.__ai_vuln_store__ || !globalThis.__ai_vuln_store__.projects || globalThis.__ai_vuln_store__.projects.length === 0) {
    const sampleScan = {
      id: 'SCN-SAMPLE-01',
      projectId: SAMPLE_PROJECT.id,
      filename: 'owasp-zap-nuclei-semgrep-consolidated.json',
      scannerType: 'generic_json',
      uploadedAt: new Date().toISOString(),
      totalRawFindings: 8,
      deduplicatedCount: SAMPLE_FINDINGS.length,
      status: 'completed',
      statusMessage: `Completed analysis: ${SAMPLE_FINDINGS.length} findings, ${SAMPLE_ATTACK_PATHS.length} attack paths.`,
      summary: {
        critical: SAMPLE_FINDINGS.filter(f => f.severity === 'Critical').length,
        high: SAMPLE_FINDINGS.filter(f => f.severity === 'High').length,
        medium: SAMPLE_FINDINGS.filter(f => f.severity === 'Medium').length,
        low: SAMPLE_FINDINGS.filter(f => f.severity === 'Low').length,
        info: SAMPLE_FINDINGS.filter(f => f.severity === 'Info').length,
      },
    };

    globalThis.__ai_vuln_store__ = {
      projects: [{ ...SAMPLE_PROJECT }],
      scans: [sampleScan],
      findings: [...SAMPLE_FINDINGS],
      attackPaths: [...SAMPLE_ATTACK_PATHS],
      remediations: [...SAMPLE_REMEDIATIONS],
      comparisons: [],
      auditLogs: [
        {
          id: 'LOG-INIT-VERCEL',
          timestamp: new Date().toISOString(),
          action: 'ENVIRONMENT_INITIALIZED',
          details: `Initialized defensive assessment workspace for ${SAMPLE_PROJECT.name}.`,
          projectId: SAMPLE_PROJECT.id,
        },
      ],
    };
  }

  return globalThis.__ai_vuln_store__;
}

export function getRuntimeStore() {
  return ensureStore();
}

export function getProjects() {
  const store = getRuntimeStore();
  return store.projects.map((project: any) => {
    const scans = store.scans.filter((scan: any) => scan.projectId === project.id);
    const findings = store.findings.filter((finding: any) => finding.projectId === project.id && finding.status !== 'verified_fixed');
    const paths = store.attackPaths.filter((path: any) => path.projectId === project.id && path.status === 'active');
    return {
      ...project,
      scanCount: scans.length,
      openFindingCount: findings.length,
      attackPathCount: paths.length,
    };
  });
}

export function getProject(id: string) {
  return getProjects().find((project: any) => project.id === id);
}

export function createProject(input: { name: string; targetScope: string; authorizedBy: string; description: string }) {
  const store = getRuntimeStore();
  const project = {
    id: `PRJ-${Date.now().toString(36).toUpperCase()}`,
    name: String(input.name).trim(),
    targetScope: String(input.targetScope).trim(),
    authorizedBy: String(input.authorizedBy || 'Authorized Security Engineer').trim(),
    description: String(input.description || '').trim(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  store.projects.push(project);
  store.auditLogs.unshift({
    id: `LOG-${Date.now()}`,
    timestamp: new Date().toISOString(),
    action: 'PROJECT_CREATED',
    details: `Project ${project.name} created. Authorized scope: ${project.targetScope}`,
    projectId: project.id,
  });
  return project;
}

export function deleteProject(id: string) {
  const store = getRuntimeStore();
  const exists = store.projects.some((p: any) => p.id === id);
  if (!exists) return false;

  store.projects = store.projects.filter((p: any) => p.id !== id);
  store.scans = store.scans.filter((s: any) => s.projectId !== id);
  store.findings = store.findings.filter((f: any) => f.projectId !== id);
  store.attackPaths = store.attackPaths.filter((a: any) => a.projectId !== id);
  store.remediations = store.remediations.filter((r: any) => r.projectId !== id);
  store.comparisons = store.comparisons.filter((c: any) => c.projectId !== id);
  store.auditLogs = store.auditLogs.filter((l: any) => l.projectId !== id);
  return true;
}

export function resetCleanDemo() {
  globalThis.__ai_vuln_store__ = null;
  const store = ensureStore();
  return store.projects[0];
}

export function getScans(projectId: string) {
  const store = getRuntimeStore();
  return store.scans.filter((scan: any) => scan.projectId === projectId);
}

export function addScan(scan: any) {
  const store = getRuntimeStore();
  store.scans.push(scan);
}

export function updateScan(id: string, updates: any) {
  const store = getRuntimeStore();
  const idx = store.scans.findIndex((scan: any) => scan.id === id);
  if (idx !== -1) {
    store.scans[idx] = { ...store.scans[idx], ...updates };
  }
}

export function getFindings(projectId: string, scanId?: string) {
  const store = getRuntimeStore();
  return store.findings.filter((finding: any) => finding.projectId === projectId && (!scanId || finding.scanId === scanId));
}

export function getFinding(id: string) {
  const store = getRuntimeStore();
  return store.findings.find((finding: any) => finding.id === id);
}

export function setFindingsForScan(scanId: string, findings: any[]) {
  const store = getRuntimeStore();
  store.findings = store.findings.filter((finding: any) => finding.scanId !== scanId);
  store.findings.push(...findings);
}

export function updateFinding(id: string, updates: any) {
  const store = getRuntimeStore();
  const idx = store.findings.findIndex((finding: any) => finding.id === id);
  if (idx !== -1) {
    store.findings[idx] = { ...store.findings[idx], ...updates };
  }
}

export function getAttackPaths(projectId: string, scanId?: string) {
  const store = getRuntimeStore();
  return store.attackPaths.filter((path: any) => path.projectId === projectId && (!scanId || path.scanId === scanId));
}

export function setAttackPathsForScan(scanId: string, paths: any[]) {
  const store = getRuntimeStore();
  store.attackPaths = store.attackPaths.filter((path: any) => path.scanId !== scanId);
  store.attackPaths.push(...paths);
}

export function getRemediations(projectId: string) {
  const store = getRuntimeStore();
  return store.remediations.filter((remediation: any) => remediation.projectId === projectId);
}

export function setRemediations(projectId: string, items: any[]) {
  const store = getRuntimeStore();
  store.remediations = store.remediations.filter((remediation: any) => remediation.projectId !== projectId);
  store.remediations.push(...items);
}

export function updateRemediation(id: string, updates: any) {
  const store = getRuntimeStore();
  const idx = store.remediations.findIndex((remediation: any) => remediation.id === id);
  if (idx !== -1) {
    store.remediations[idx] = { ...store.remediations[idx], ...updates };
  }
}

export function getComparisons(projectId: string) {
  const store = getRuntimeStore();
  return store.comparisons.filter((comparison: any) => comparison.projectId === projectId);
}

export function addComparison(comparison: any) {
  const store = getRuntimeStore();
  store.comparisons = store.comparisons.filter((item: any) => item.id !== comparison.id);
  store.comparisons.unshift(comparison);
}

export function getDashboardMetrics(projectId: string) {
  const store = getRuntimeStore();
  const findings = store.findings.filter((finding: any) => finding.projectId === projectId);
  const activePaths = store.attackPaths.filter((path: any) => path.projectId === projectId && path.status === 'active');
  const remediations = store.remediations.filter((remediation: any) => remediation.projectId === projectId);

  const criticalFindings = findings.filter((finding: any) => finding.severity === 'Critical' && finding.status !== 'verified_fixed').length;
  const highFindings = findings.filter((finding: any) => finding.severity === 'High' && finding.status !== 'verified_fixed').length;
  const mediumFindings = findings.filter((finding: any) => finding.severity === 'Medium' && finding.status !== 'verified_fixed').length;
  const lowFindings = findings.filter((finding: any) => finding.severity === 'Low' && finding.status !== 'verified_fixed').length;
  const infoFindings = findings.filter((finding: any) => finding.severity === 'Info' && finding.status !== 'verified_fixed').length;
  const criticalAttackPaths = activePaths.filter((path: any) => path.severity === 'Critical').length;
  const assets = Array.from(new Set(findings.map((finding: any) => finding.asset)));
  const unresolved = remediations.filter((remediation: any) => remediation.status !== 'verified_fixed').length;
  const resolved = remediations.filter((remediation: any) => remediation.status === 'verified_fixed').length;

  const avgRisk = activePaths.length > 0
    ? Math.round(activePaths.reduce((acc: number, path: any) => acc + (path.contextualScore || 0), 0) / activePaths.length)
    : criticalFindings > 0 ? 75 : highFindings > 0 ? 55 : 20;

  let posture: 'CRITICAL RISK' | 'ELEVATED RISK' | 'MODERATE RISK' | 'SECURE POSTURE' = 'SECURE POSTURE';
  if (criticalAttackPaths > 0 || criticalFindings > 0) posture = 'CRITICAL RISK';
  else if (activePaths.length > 0 || highFindings > 0) posture = 'ELEVATED RISK';
  else if (mediumFindings > 0) posture = 'MODERATE RISK';

  return {
    totalFindings: findings.length,
    uniqueFindings: findings.length,
    criticalFindings,
    highFindings,
    mediumFindings,
    lowFindings,
    infoFindings,
    activeAttackPaths: activePaths.length,
    criticalAttackPaths,
    affectedAssets: assets,
    unresolvedRemediations: unresolved,
    resolvedRemediations: resolved,
    averageContextualRisk: avgRisk,
    postureRating: posture,
  };
}

export function getAuditLogs(projectId?: string) {
  const store = getRuntimeStore();
  return projectId ? store.auditLogs.filter((log: any) => log.projectId === projectId || !log.projectId) : store.auditLogs;
}

import fs from 'fs';
import path from 'path';
import { Project, Scan, NormalizedFinding, FindingRelationship, AttackPath, RemediationItem, ScanComparison, DashboardMetrics } from '../src/types';
import { SAMPLE_PROJECT, SAMPLE_FINDINGS, SAMPLE_ATTACK_PATHS, SAMPLE_REMEDIATIONS } from './sampleData';

const DATA_DIR = path.join(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

export interface DatabaseSchema {
  projects: Project[];
  scans: Scan[];
  findings: NormalizedFinding[];
  relationships: FindingRelationship[];
  attackPaths: AttackPath[];
  remediations: RemediationItem[];
  comparisons: ScanComparison[];
  auditLogs: {
    id: string;
    timestamp: string;
    action: string;
    details: string;
    projectId?: string;
  }[];
}

declare global {
  var __ai_vuln_db__: DatabaseSchema | undefined;
}

class Database {
  private get data(): DatabaseSchema {
    if (!globalThis.__ai_vuln_db__) {
      this.init();
    }
    return globalThis.__ai_vuln_db__!;
  }

  private set data(val: DatabaseSchema) {
    globalThis.__ai_vuln_db__ = val;
  }

  constructor() {
    this.init();
  }

  private init() {
    if (globalThis.__ai_vuln_db__ && globalThis.__ai_vuln_db__.projects?.length > 0) {
      return;
    }

    try {
      if (fs.existsSync(DB_FILE)) {
        const raw = fs.readFileSync(DB_FILE, 'utf-8');
        globalThis.__ai_vuln_db__ = JSON.parse(raw);
        if (!globalThis.__ai_vuln_db__?.projects || globalThis.__ai_vuln_db__.projects.length === 0) {
          this.seedInitialData();
          this.save();
        }
      } else {
        this.seedInitialData();
        this.save();
      }
    } catch {
      this.seedInitialData();
    }
  }

  private save() {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      fs.writeFileSync(DB_FILE, JSON.stringify(this.data, null, 2), 'utf-8');
    } catch {}
  }

  public seedInitialData() {
    const sampleScan: Scan = {
      id: 'SCN-SAMPLE-01',
      projectId: SAMPLE_PROJECT.id,
      filename: 'owasp-zap-nuclei-semgrep-consolidated.json',
      scannerType: 'generic_json',
      uploadedAt: new Date().toISOString(),
      totalRawFindings: 8,
      deduplicatedCount: SAMPLE_FINDINGS.length,
      status: 'completed',
      statusMessage: `Completed analysis: ${SAMPLE_FINDINGS.length} findings, ${SAMPLE_ATTACK_PATHS.length} attack paths, ${SAMPLE_REMEDIATIONS.length} remediation actions.`,
      summary: {
        critical: SAMPLE_FINDINGS.filter(f => f.severity === 'Critical').length,
        high: SAMPLE_FINDINGS.filter(f => f.severity === 'High').length,
        medium: SAMPLE_FINDINGS.filter(f => f.severity === 'Medium').length,
        low: SAMPLE_FINDINGS.filter(f => f.severity === 'Low').length,
        info: SAMPLE_FINDINGS.filter(f => f.severity === 'Info').length,
      },
    };

    this.data = {
      projects: [{ ...SAMPLE_PROJECT }],
      scans: [sampleScan],
      findings: [...SAMPLE_FINDINGS],
      relationships: [],
      attackPaths: [...SAMPLE_ATTACK_PATHS],
      remediations: [...SAMPLE_REMEDIATIONS],
      comparisons: [],
      auditLogs: [
        {
          id: `LOG-INIT-1`,
          timestamp: new Date().toISOString(),
          action: 'ENVIRONMENT_INITIALIZED',
          details: `Seeded defensive assessment workspace for ${SAMPLE_PROJECT.name} (${SAMPLE_PROJECT.targetScope}).`,
          projectId: SAMPLE_PROJECT.id,
        },
      ],
    };
    this.save();
  }

  public resetCleanDemo(): Project {
    this.seedInitialData();
    return this.data.projects[0];
  }

  public logAudit(projectId: string | undefined, action: string, details: string) {
    this.data.auditLogs.unshift({
      id: `LOG-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp: new Date().toISOString(),
      action,
      details,
      projectId,
    });
    // Keep max 500 audit entries
    if (this.data.auditLogs.length > 500) {
      this.data.auditLogs = this.data.auditLogs.slice(0, 500);
    }
    this.save();
  }

  // --- Projects ---
  public getProjects(): Project[] {
    return this.data.projects.map(p => {
      const scans = this.data.scans.filter(s => s.projectId === p.id);
      const findings = this.data.findings.filter(f => f.projectId === p.id && f.status !== 'verified_fixed');
      const paths = this.data.attackPaths.filter(a => a.projectId === p.id && a.status === 'active');
      return {
        ...p,
        scanCount: scans.length,
        openFindingCount: findings.length,
        attackPathCount: paths.length,
      };
    });
  }

  public getProject(id: string): Project | undefined {
    return this.getProjects().find(p => p.id === id);
  }

  public createProject(input: { name: string; targetScope: string; authorizedBy: string; description: string }): Project {
    const p: Project = {
      id: `PRJ-${Date.now().toString(36).toUpperCase()}`,
      name: input.name.trim(),
      targetScope: input.targetScope.trim(),
      authorizedBy: input.authorizedBy.trim() || 'Authorized Security Engineer',
      description: input.description.trim(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    this.data.projects.push(p);
    this.logAudit(p.id, 'PROJECT_CREATED', `Project ${p.name} created. Authorized scope: ${p.targetScope}`);
    this.save();
    return p;
  }

  public deleteProject(projectId: string): boolean {
    const exists = this.data.projects.some(p => p.id === projectId);
    if (!exists) return false;

    this.data.projects = this.data.projects.filter(p => p.id !== projectId);
    this.data.scans = this.data.scans.filter(s => s.projectId !== projectId);
    this.data.findings = this.data.findings.filter(f => f.projectId !== projectId);
    this.data.attackPaths = this.data.attackPaths.filter(a => a.projectId !== projectId);
    this.data.remediations = this.data.remediations.filter(r => r.projectId !== projectId);
    this.data.comparisons = this.data.comparisons.filter(c => c.projectId !== projectId);
    this.data.relationships = this.data.relationships.filter(rel => rel.projectId !== projectId);
    this.data.auditLogs = this.data.auditLogs.filter(l => l.projectId !== projectId);

    this.save();
    return true;
  }

  // --- Scans ---
  public getScans(projectId: string): Scan[] {
    return this.data.scans.filter(s => s.projectId === projectId);
  }

  public getScan(id: string): Scan | undefined {
    return this.data.scans.find(s => s.id === id);
  }

  public addScan(scan: Scan) {
    this.data.scans.push(scan);
    this.save();
  }

  public updateScan(id: string, updates: Partial<Scan>) {
    const idx = this.data.scans.findIndex(s => s.id === id);
    if (idx !== -1) {
      this.data.scans[idx] = { ...this.data.scans[idx], ...updates };
      this.save();
    }
  }

  // --- Findings ---
  public getFindings(projectId: string, scanId?: string): NormalizedFinding[] {
    return this.data.findings.filter(f => f.projectId === projectId && (!scanId || f.scanId === scanId));
  }

  public getFinding(id: string): NormalizedFinding | undefined {
    return this.data.findings.find(f => f.id === id);
  }

  public setFindingsForScan(scanId: string, findings: NormalizedFinding[]) {
    // Remove old findings for this scan if any
    this.data.findings = this.data.findings.filter(f => f.scanId !== scanId);
    this.data.findings.push(...findings);
    this.save();
  }

  public updateFinding(id: string, updates: Partial<NormalizedFinding>) {
    const idx = this.data.findings.findIndex(f => f.id === id);
    if (idx !== -1) {
      this.data.findings[idx] = { ...this.data.findings[idx], ...updates };
      this.save();
    }
  }

  // --- Attack Paths ---
  public getAttackPaths(projectId: string, scanId?: string): AttackPath[] {
    return this.data.attackPaths.filter(p => p.projectId === projectId && (!scanId || p.scanId === scanId));
  }

  public setAttackPathsForScan(scanId: string, paths: AttackPath[]) {
    this.data.attackPaths = this.data.attackPaths.filter(p => p.scanId !== scanId);
    this.data.attackPaths.push(...paths);
    this.save();
  }

  public getAttackPath(id: string): AttackPath | undefined {
    return this.data.attackPaths.find(p => p.id === id);
  }

  // --- Remediations ---
  public getRemediations(projectId: string): RemediationItem[] {
    return this.data.remediations.filter(r => r.projectId === projectId);
  }

  public setRemediations(projectId: string, items: RemediationItem[]) {
    this.data.remediations = this.data.remediations.filter(r => r.projectId !== projectId);
    this.data.remediations.push(...items);
    this.save();
  }

  public updateRemediation(id: string, updates: Partial<RemediationItem>) {
    const idx = this.data.remediations.findIndex(r => r.id === id);
    if (idx !== -1) {
      this.data.remediations[idx] = { ...this.data.remediations[idx], ...updates };
      this.save();
    }
  }

  // --- Comparisons ---
  public getComparisons(projectId: string): ScanComparison[] {
    return this.data.comparisons.filter(c => c.projectId === projectId);
  }

  public addComparison(comparison: ScanComparison) {
    this.data.comparisons = this.data.comparisons.filter(c => c.id !== comparison.id);
    this.data.comparisons.unshift(comparison);
    this.save();
  }

  // --- Metrics ---
  public getDashboardMetrics(projectId: string): DashboardMetrics {
    const findings = this.data.findings.filter(f => f.projectId === projectId);
    const activePaths = this.data.attackPaths.filter(p => p.projectId === projectId && p.status === 'active');
    const remediations = this.data.remediations.filter(r => r.projectId === projectId);

    const criticalFindings = findings.filter(f => f.severity === 'Critical' && f.status !== 'verified_fixed').length;
    const highFindings = findings.filter(f => f.severity === 'High' && f.status !== 'verified_fixed').length;
    const mediumFindings = findings.filter(f => f.severity === 'Medium' && f.status !== 'verified_fixed').length;
    const lowFindings = findings.filter(f => f.severity === 'Low' && f.status !== 'verified_fixed').length;
    const infoFindings = findings.filter(f => f.severity === 'Info' && f.status !== 'verified_fixed').length;

    const criticalAttackPaths = activePaths.filter(p => p.severity === 'Critical').length;
    const assets = Array.from(new Set(findings.map(f => f.asset)));

    const unresolved = remediations.filter(r => r.status !== 'verified_fixed').length;
    const resolved = remediations.filter(r => r.status === 'verified_fixed').length;

    const avgRisk = activePaths.length > 0
      ? Math.round(activePaths.reduce((acc, p) => acc + p.contextualScore, 0) / activePaths.length)
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

  public getAuditLogs(projectId?: string) {
    return projectId 
      ? this.data.auditLogs.filter(l => l.projectId === projectId || !l.projectId)
      : this.data.auditLogs;
  }
}

export const db = new Database();

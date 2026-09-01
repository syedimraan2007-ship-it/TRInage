import express from 'express';
import dotenv from 'dotenv';
import { db } from './db';
import { SAMPLE_RAW_FILES } from './sampleData';
import { detectAndParseScan } from './parsers/index';
import { deduplicateFindings } from './services/deduplication';
import { aiTriageFindings, aiCorrelateAndBuildAttackPaths, aiGenerateRemediationGuidance } from './services/gemini';
import { generateRemediationQueue } from './services/remediationEngine';
import { compareScans } from './services/comparisonEngine';
import { AssessmentReport, Scan } from '../src/types';

dotenv.config();

export function createApiApp() {
  const app = express();
  const router = express.Router();

  // CORS Middleware
  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }
    next();
  });

  // JSON Body Parser with 50mb limit for large scanner logs
  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ extended: true, limit: '50mb' }));

  // --- API Routes on Router ---

  // Health
  router.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // Projects
  router.get('/projects', (req, res) => {
    res.json(db.getProjects());
  });

  router.post('/projects', (req, res) => {
    const { name, targetScope, authorizedBy, description } = req.body || {};
    if (!name || !targetScope) {
      return res.status(400).json({ error: 'Project name and authorized target scope are required.' });
    }
    const project = db.createProject({ name, targetScope, authorizedBy, description: description || '' });
    res.json(project);
  });

  router.post('/projects/reset-demo', (req, res) => {
    const proj = db.resetCleanDemo();
    res.json({ success: true, project: proj });
  });

  router.get('/projects/:id', (req, res) => {
    const project = db.getProject(req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });
    res.json(project);
  });

  router.delete('/projects/:id', (req, res) => {
    const success = db.deleteProject(req.params.id);
    if (!success) return res.status(404).json({ error: 'Project not found.' });
    res.json({ success: true, message: 'Project deleted successfully.' });
  });

  // Scans
  router.get('/projects/:projectId/scans', (req, res) => {
    res.json(db.getScans(req.params.projectId));
  });

  // Upload Scan Content
  router.post('/projects/:projectId/scans', async (req, res) => {
    const { projectId } = req.params;
    const { filename, rawContent } = req.body || {};

    if (!rawContent || !filename) {
      return res.status(400).json({ error: 'File content and filename are required.' });
    }

    const scanId = `SCN-${Date.now().toString(36).toUpperCase()}`;

    try {
      const parsed = detectAndParseScan(rawContent, filename, projectId, scanId);
      const dedup = deduplicateFindings(parsed.findings, parsed.scannerType, scanId, projectId);

      const newScan: Scan = {
        id: scanId,
        projectId,
        filename,
        scannerType: parsed.scannerType as any,
        uploadedAt: new Date().toISOString(),
        totalRawFindings: dedup.rawCount,
        deduplicatedCount: dedup.deduplicatedCount,
        status: 'normalized',
        statusMessage: `Normalized ${dedup.rawCount} raw findings into ${dedup.deduplicatedCount} canonical findings.`,
        summary: {
          critical: dedup.canonicalFindings.filter(f => f.severity === 'Critical').length,
          high: dedup.canonicalFindings.filter(f => f.severity === 'High').length,
          medium: dedup.canonicalFindings.filter(f => f.severity === 'Medium').length,
          low: dedup.canonicalFindings.filter(f => f.severity === 'Low').length,
          info: dedup.canonicalFindings.filter(f => f.severity === 'Info').length,
        },
      };

      db.addScan(newScan);
      db.setFindingsForScan(scanId, dedup.canonicalFindings);
      db.logAudit(projectId, 'SCAN_UPLOADED', `Scan ${filename} parsed as ${parsed.scannerType} (${dedup.rawCount} raw items).`);

      res.json({ scan: newScan, deduplication: dedup });
    } catch (err: any) {
      res.status(400).json({ error: err.message || 'Failed to parse security scan format.' });
    }
  });

  // Process / Pipeline Trigger
  router.post('/projects/:projectId/scans/:scanId/process', async (req, res) => {
    const { projectId, scanId } = req.params;
    const scan = db.getScan(scanId);
    if (!scan) return res.status(404).json({ error: 'Scan not found.' });

    let findings = db.getFindings(projectId, scanId);
    if (findings.length === 0) {
      return res.status(400).json({ error: 'No findings available to process.' });
    }

    try {
      db.updateScan(scanId, { status: 'analyzing', statusMessage: 'Performing contextual AI triage & evidence analysis...' });
      findings = await aiTriageFindings(findings);
      db.setFindingsForScan(scanId, findings);

      db.updateScan(scanId, { status: 'correlating', statusMessage: 'Synthesizing multi-stage attack paths & privilege chains...' });
      const paths = await aiCorrelateAndBuildAttackPaths(findings, projectId, scanId);
      db.setAttackPathsForScan(scanId, paths);

      db.updateScan(scanId, { status: 'building_paths', statusMessage: 'Calculating high-leverage remediation priorities...' });
      const remediations = generateRemediationQueue(findings, paths, projectId);
      db.setRemediations(projectId, remediations);

      db.updateScan(scanId, {
        status: 'completed',
        statusMessage: `Completed analysis: ${findings.length} findings, ${paths.length} attack paths, ${remediations.length} remediation actions.`,
        summary: {
          critical: findings.filter(f => f.severity === 'Critical').length,
          high: findings.filter(f => f.severity === 'High').length,
          medium: findings.filter(f => f.severity === 'Medium').length,
          low: findings.filter(f => f.severity === 'Low').length,
          info: findings.filter(f => f.severity === 'Info').length,
        },
      });

      db.logAudit(projectId, 'ANALYSIS_COMPLETED', `AI Pipeline completed for scan ${scan.filename}: ${paths.length} attack paths prioritized.`);

      res.json({
        success: true,
        findingsCount: findings.length,
        attackPathsCount: paths.length,
        remediationsCount: remediations.length,
      });
    } catch (err: any) {
      db.updateScan(scanId, { status: 'failed', statusMessage: `Processing error: ${err.message}` });
      res.status(500).json({ error: err.message });
    }
  });

  // Findings
  router.get('/projects/:projectId/findings', (req, res) => {
    const { scanId, severity, asset, status, search } = req.query;
    let findings = db.getFindings(req.params.projectId, scanId as string | undefined);

    if (severity) {
      findings = findings.filter(f => f.severity.toLowerCase() === String(severity).toLowerCase());
    }
    if (asset) {
      findings = findings.filter(f => f.asset.toLowerCase().includes(String(asset).toLowerCase()));
    }
    if (status) {
      findings = findings.filter(f => f.status === status);
    }
    if (search) {
      const q = String(search).toLowerCase();
      findings = findings.filter(f =>
        f.title.toLowerCase().includes(q) ||
        f.endpoint?.toLowerCase().includes(q) ||
        f.cwe?.toLowerCase().includes(q) ||
        f.cve?.toLowerCase().includes(q) ||
        f.vulnerabilityCategory.toLowerCase().includes(q)
      );
    }

    res.json(findings);
  });

  router.get('/projects/:projectId/findings/:id', (req, res) => {
    const finding = db.getFinding(req.params.id);
    if (!finding) return res.status(404).json({ error: 'Finding not found.' });
    res.json(finding);
  });

  router.patch('/projects/:projectId/findings/:id', (req, res) => {
    const { status } = req.body || {};
    db.updateFinding(req.params.id, { status });
    db.logAudit(req.params.projectId, 'FINDING_UPDATED', `Finding ${req.params.id} marked as ${status}`);
    res.json(db.getFinding(req.params.id));
  });

  // Attack Paths
  router.get('/projects/:projectId/attack-paths', (req, res) => {
    const { scanId } = req.query;
    const paths = db.getAttackPaths(req.params.projectId, scanId as string | undefined);
    res.json(paths);
  });

  router.get('/projects/:projectId/attack-paths/:id', (req, res) => {
    const pathItem = db.getAttackPath(req.params.id);
    if (!pathItem) return res.status(404).json({ error: 'Attack path not found.' });
    res.json(pathItem);
  });

  // Remediations
  router.get('/projects/:projectId/remediations', (req, res) => {
    res.json(db.getRemediations(req.params.projectId));
  });

  router.patch('/projects/:projectId/remediations/:id', (req, res) => {
    const { status, assignedTo } = req.body || {};
    db.updateRemediation(req.params.id, { status, assignedTo });
    db.logAudit(req.params.projectId, 'REMEDIATION_UPDATED', `Remediation ${req.params.id} updated (status: ${status})`);
    res.json(db.getRemediations(req.params.projectId).find(r => r.id === req.params.id));
  });

  // AI Remediation Guide
  router.post('/projects/:projectId/remediations/:id/ai-guide', async (req, res) => {
    const items = db.getRemediations(req.params.projectId);
    const item = items.find(r => r.id === req.params.id);
    if (!item) return res.status(404).json({ error: 'Remediation item not found.' });

    const findings = db.getFindings(req.params.projectId);
    try {
      const guidance = await aiGenerateRemediationGuidance(item, findings);
      db.updateRemediation(req.params.id, { aiGuidance: guidance });
      res.json(guidance);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Scan Comparison
  router.get('/projects/:projectId/comparisons', (req, res) => {
    res.json(db.getComparisons(req.params.projectId));
  });

  router.post('/projects/:projectId/compare', async (req, res) => {
    const { projectId } = req.params;
    const { scan1Id, scan2Id } = req.body || {};

    const scan1 = db.getScan(scan1Id);
    const scan2 = db.getScan(scan2Id);

    if (!scan1 || !scan2) {
      return res.status(400).json({ error: 'Both baseline and comparison scans must exist.' });
    }

    const scan1Findings = db.getFindings(projectId, scan1Id);
    const scan2Findings = db.getFindings(projectId, scan2Id);
    const scan1Paths = db.getAttackPaths(projectId, scan1Id);
    const scan2Paths = db.getAttackPaths(projectId, scan2Id);

    try {
      const comparison = await compareScans(scan1, scan1Findings, scan1Paths, scan2, scan2Findings, scan2Paths);
      db.addComparison(comparison);
      db.logAudit(projectId, 'SCANS_COMPARED', `Compared ${scan1.filename} with ${scan2.filename}. Eliminated ${comparison.eliminatedPathIds.length} attack paths.`);
      res.json(comparison);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Dashboard Metrics
  router.get('/projects/:projectId/dashboard', (req, res) => {
    res.json(db.getDashboardMetrics(req.params.projectId));
  });

  // Comprehensive Report
  router.get('/projects/:projectId/report', (req, res) => {
    const { projectId } = req.params;
    const project = db.getProject(projectId);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const scans = db.getScans(projectId);
    const latestScan = scans[scans.length - 1] || { id: 'N/A', filename: 'None' };
    const metrics = db.getDashboardMetrics(projectId);
    const paths = db.getAttackPaths(projectId);
    const remediations = db.getRemediations(projectId);
    const findings = db.getFindings(projectId);

    const assetMap = new Map<string, { count: number; maxSev: string; critPaths: number }>();
    findings.forEach(f => {
      if (!assetMap.has(f.asset)) {
        assetMap.set(f.asset, { count: 0, maxSev: 'Low', critPaths: 0 });
      }
      const entry = assetMap.get(f.asset)!;
      entry.count++;
      if (f.severity === 'Critical') entry.maxSev = 'Critical';
      else if (f.severity === 'High' && entry.maxSev !== 'Critical') entry.maxSev = 'High';
    });

    paths.forEach(p => {
      if (p.severity === 'Critical') {
        p.participatingAssets.forEach(a => {
          if (assetMap.has(a)) assetMap.get(a)!.critPaths++;
        });
      }
    });

    const highRiskAssets = Array.from(assetMap.entries()).map(([asset, data]) => ({
      asset,
      findingCount: data.count,
      maxSeverity: data.maxSev as any,
      criticalPathsCount: data.critPaths,
    }));

    const report: AssessmentReport = {
      project,
      scan: latestScan as any,
      metrics,
      topAttackPaths: paths.slice(0, 10),
      prioritizedRemediations: remediations.slice(0, 10),
      highRiskAssets,
      methodology: 'Normalized heterogeneous scanner ingestion, deterministic deduplication clustering, context-calibrated AI triage, graph-based attack path modeling, and deterministic mathematical risk prioritization.',
      aiLimitations: 'All AI conclusions are strictly derived from supplied scanner evidence. No unauthorized exploitation was performed. Testing is restricted to explicitly authorized assets.',
      generatedAt: new Date().toISOString(),
    };

    res.json(report);
  });

  // Sample Datasets & 1-Click Scanner Loaders
  router.get('/samples', (req, res) => {
    res.json([
      {
        id: 'zap',
        name: 'OWASP ZAP API Scan',
        format: 'JSON Report',
        scanner: 'OWASP ZAP 2.15',
        description: 'DAST scan finding SSRF in webhook dispatcher and permissive CORS misconfiguration.',
        filename: 'owasp-zap-gateway-scan.json',
      },
      {
        id: 'nuclei',
        name: 'ProjectDiscovery Nuclei Scan',
        format: 'JSON Output',
        scanner: 'Nuclei v3.2',
        description: 'Vulnerability scan uncovering unauthenticated Redis cache and exposed cloud metadata.',
        filename: 'nuclei-internal-services.json',
      },
      {
        id: 'semgrep',
        name: 'Semgrep SAST Code Scan',
        format: 'JSON Findings',
        scanner: 'Semgrep 1.68',
        description: 'Static code analysis detecting SQL injection in ledger reconciliation and hardcoded JWT secrets.',
        filename: 'semgrep-auth-sast.json',
      },
      {
        id: 'postFix',
        name: 'Post-Remediation Verification Scan',
        format: 'JSON Report',
        scanner: 'Automated Post-Fix',
        description: 'Follow-up scan showing resolved SSRF, SQLi, and Redis access for delta verification.',
        filename: 'post-remediation-verification.json',
      },
    ]);
  });

  router.post('/load-sample', async (req, res) => {
    const { sampleId, projectId } = req.body || {};
    const key = sampleId as keyof typeof SAMPLE_RAW_FILES;

    if (!SAMPLE_RAW_FILES[key]) {
      return res.status(404).json({ error: `Sample scan '${sampleId}' not found.` });
    }

    const rawContent = SAMPLE_RAW_FILES[key];
    const filenames: Record<string, string> = {
      zap: 'owasp-zap-gateway-scan.json',
      nuclei: 'nuclei-internal-services.json',
      semgrep: 'semgrep-auth-sast.json',
      postFix: 'post-remediation-verification.json',
    };

    const filename = filenames[sampleId] || 'sample-scan.json';
    const targetProjectId = projectId || db.getProjects()[0]?.id || db.resetCleanDemo().id;
    const scanId = `SCN-${Date.now().toString(36).toUpperCase()}`;

    try {
      const parsed = detectAndParseScan(rawContent, filename, targetProjectId, scanId);
      const dedup = deduplicateFindings(parsed.findings, parsed.scannerType, scanId, targetProjectId);

      const newScan: Scan = {
        id: scanId,
        projectId,
        filename,
        scannerType: parsed.scannerType as any,
        uploadedAt: new Date().toISOString(),
        totalRawFindings: dedup.rawCount,
        deduplicatedCount: dedup.deduplicatedCount,
        status: 'normalized',
        statusMessage: `Normalized ${dedup.rawCount} raw findings into ${dedup.deduplicatedCount} canonical findings.`,
        summary: {
          critical: dedup.canonicalFindings.filter(f => f.severity === 'Critical').length,
          high: dedup.canonicalFindings.filter(f => f.severity === 'High').length,
          medium: dedup.canonicalFindings.filter(f => f.severity === 'Medium').length,
          low: dedup.canonicalFindings.filter(f => f.severity === 'Low').length,
          info: dedup.canonicalFindings.filter(f => f.severity === 'Info').length,
        },
      };

      db.addScan(newScan);
      db.setFindingsForScan(scanId, dedup.canonicalFindings);
      db.logAudit(targetProjectId, 'SAMPLE_LOADED', `Sample dataset '${filename}' loaded.`);

      res.json({ scan: newScan, deduplication: dedup, rawContent });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // Audit Logs
  router.get('/audit-logs', (req, res) => {
    const { projectId } = req.query;
    res.json(db.getAuditLogs(projectId as string | undefined));
  });

  // Mount router at both '/api' and '/'
  app.use('/api', router);
  app.use('/', router);

  // Global JSON Error Handler
  app.use((err: any, req: any, res: any, next: any) => {
    console.error('API Error:', err);
    res.status(500).json({ error: err.message || 'Internal Server Error' });
  });

  return app;
}

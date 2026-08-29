import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';
import { db } from './server/db';
import { detectAndParseScan } from './server/parsers/index';
import { deduplicateFindings } from './server/services/deduplication';
import { aiTriageFindings, aiCorrelateAndBuildAttackPaths, aiGenerateRemediationGuidance } from './server/services/gemini';
import { generateRemediationQueue } from './server/services/remediationEngine';
import { compareScans } from './server/services/comparisonEngine';
import { AssessmentReport, Scan } from './src/types';

dotenv.config();

async function startServer() {
  const app = express();
  const PORT = 3000;

  // JSON Body Parser with 50mb limit for large scanner logs
  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ extended: true, limit: '50mb' }));

  // --- API Routes ---

  // Health
  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // Projects
  app.get('/api/projects', (req, res) => {
    res.json(db.getProjects());
  });

  app.post('/api/projects', (req, res) => {
    const { name, targetScope, authorizedBy, description } = req.body;
    if (!name || !targetScope) {
      return res.status(400).json({ error: 'Project name and authorized target scope are required.' });
    }
    const project = db.createProject({ name, targetScope, authorizedBy, description: description || '' });
    res.json(project);
  });

  app.get('/api/projects/:id', (req, res) => {
    const project = db.getProject(req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found.' });
    res.json(project);
  });

  // Scans
  app.get('/api/projects/:projectId/scans', (req, res) => {
    res.json(db.getScans(req.params.projectId));
  });

  // Upload Scan Content
  app.post('/api/projects/:projectId/scans', async (req, res) => {
    const { projectId } = req.params;
    const { filename, rawContent } = req.body;

    if (!rawContent || !filename) {
      return res.status(400).json({ error: 'File content and filename are required.' });
    }

    const scanId = `SCN-${Date.now().toString(36).toUpperCase()}`;

    try {
      // 1. Validate & Parse
      const parsed = detectAndParseScan(rawContent, filename, projectId, scanId);

      // 2. Deduplicate
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

  // Process / Pipeline Trigger (AI Triage + Attack Graph + Prioritization)
  app.post('/api/projects/:projectId/scans/:scanId/process', async (req, res) => {
    const { projectId, scanId } = req.params;
    const scan = db.getScan(scanId);
    if (!scan) return res.status(404).json({ error: 'Scan not found.' });

    let findings = db.getFindings(projectId, scanId);
    if (findings.length === 0) {
      return res.status(400).json({ error: 'No findings available to process.' });
    }

    try {
      // Step 1: AI Triage
      db.updateScan(scanId, { status: 'analyzing', statusMessage: 'Performing contextual AI triage & evidence analysis...' });
      findings = await aiTriageFindings(findings);
      db.setFindingsForScan(scanId, findings);

      // Step 2: Correlate & Build Attack Paths
      db.updateScan(scanId, { status: 'correlating', statusMessage: 'Synthesizing multi-stage attack paths & privilege chains...' });
      const paths = await aiCorrelateAndBuildAttackPaths(findings, projectId, scanId);
      db.setAttackPathsForScan(scanId, paths);

      // Step 3: Prioritize Remediations
      db.updateScan(scanId, { status: 'building_paths', statusMessage: 'Calculating high-leverage remediation priorities...' });
      const remediations = generateRemediationQueue(findings, paths, projectId);
      db.setRemediations(projectId, remediations);

      // Step 4: Finalize
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
  app.get('/api/projects/:projectId/findings', (req, res) => {
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

  app.get('/api/projects/:projectId/findings/:id', (req, res) => {
    const finding = db.getFinding(req.params.id);
    if (!finding) return res.status(404).json({ error: 'Finding not found.' });
    res.json(finding);
  });

  app.patch('/api/projects/:projectId/findings/:id', (req, res) => {
    const { status } = req.body;
    db.updateFinding(req.params.id, { status });
    db.logAudit(req.params.projectId, 'FINDING_UPDATED', `Finding ${req.params.id} marked as ${status}`);
    res.json(db.getFinding(req.params.id));
  });

  // Attack Paths
  app.get('/api/projects/:projectId/attack-paths', (req, res) => {
    const { scanId } = req.query;
    const paths = db.getAttackPaths(req.params.projectId, scanId as string | undefined);
    res.json(paths);
  });

  app.get('/api/projects/:projectId/attack-paths/:id', (req, res) => {
    const pathItem = db.getAttackPath(req.params.id);
    if (!pathItem) return res.status(404).json({ error: 'Attack path not found.' });
    res.json(pathItem);
  });

  // Remediations
  app.get('/api/projects/:projectId/remediations', (req, res) => {
    res.json(db.getRemediations(req.params.projectId));
  });

  app.patch('/api/projects/:projectId/remediations/:id', (req, res) => {
    const { status, assignedTo } = req.body;
    db.updateRemediation(req.params.id, { status, assignedTo });
    db.logAudit(req.params.projectId, 'REMEDIATION_UPDATED', `Remediation ${req.params.id} updated (status: ${status})`);
    res.json(db.getRemediations(req.params.projectId).find(r => r.id === req.params.id));
  });

  // AI Remediation Guide
  app.post('/api/projects/:projectId/remediations/:id/ai-guide', async (req, res) => {
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
  app.get('/api/projects/:projectId/comparisons', (req, res) => {
    res.json(db.getComparisons(req.params.projectId));
  });

  app.post('/api/projects/:projectId/compare', async (req, res) => {
    const { projectId } = req.params;
    const { scan1Id, scan2Id } = req.body;

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
  app.get('/api/projects/:projectId/dashboard', (req, res) => {
    res.json(db.getDashboardMetrics(req.params.projectId));
  });

  // Comprehensive Report
  app.get('/api/projects/:projectId/report', (req, res) => {
    const { projectId } = req.params;
    const project = db.getProject(projectId);
    if (!project) return res.status(404).json({ error: 'Project not found.' });

    const scans = db.getScans(projectId);
    const latestScan = scans[scans.length - 1] || { id: 'N/A', filename: 'None' };
    const metrics = db.getDashboardMetrics(projectId);
    const paths = db.getAttackPaths(projectId);
    const remediations = db.getRemediations(projectId);
    const findings = db.getFindings(projectId);

    // High risk assets summary
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

  // Sample Datasets & Lab Loader (returns empty)
  app.get('/api/samples', (req, res) => {
    res.json([]);
  });

  app.post('/api/load-sample', async (req, res) => {
    res.status(404).json({ error: 'Pre-packaged sample datasets have been removed.' });
  });

  // Audit Logs
  app.get('/api/audit-logs', (req, res) => {
    const { projectId } = req.query;
    res.json(db.getAuditLogs(projectId as string | undefined));
  });

  // Vite middleware for development vs static production serving
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`AI Vulnerability Triage & Attack-Path Prioritizer server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();

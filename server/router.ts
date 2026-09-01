import { db } from './db';
import { SAMPLE_RAW_FILES } from './sampleData';
import { detectAndParseScan } from './parsers/index';
import { deduplicateFindings } from './services/deduplication';
import { aiTriageFindings, aiCorrelateAndBuildAttackPaths, aiGenerateRemediationGuidance } from './services/gemini';
import { generateRemediationQueue } from './services/remediationEngine';
import { compareScans } from './services/comparisonEngine';
import { AssessmentReport, Scan } from '../src/types';

export async function handleApiRequest(req: any, res: any) {
  // CORS Headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Universal JSON sender compatible with Vercel and Node.js
  const sendJson = (code: number, data: any) => {
    res.setHeader('Content-Type', 'application/json');
    if (typeof res.status === 'function') {
      res.status(code);
    } else {
      res.statusCode = code;
    }
    if (typeof res.json === 'function') {
      return res.json(data);
    }
    return res.end(JSON.stringify(data));
  };

  // Determine path from Vercel catch-all query or standard URL
  let pathname = '';
  if (req.query && req.query.path) {
    const rawPath = Array.isArray(req.query.path) ? req.query.path.join('/') : String(req.query.path);
    pathname = '/' + rawPath.replace(/^\/+/, '');
  } else {
    try {
      const urlObj = new URL(req.url || '/', 'http://localhost');
      pathname = urlObj.pathname;
      if (pathname.startsWith('/api')) {
        pathname = pathname.slice(4) || '/';
      }
    } catch {
      pathname = '/';
    }
  }

  // Helper to get query param from req.query or url search params
  const getQuery = (param: string): string | null => {
    if (req.query && req.query[param] !== undefined) {
      return String(req.query[param]);
    }
    try {
      const urlObj = new URL(req.url || '/', 'http://localhost');
      return urlObj.searchParams.get(param);
    } catch {
      return null;
    }
  };

  // Helper to parse JSON body
  let body = req.body;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch {}
  }
  body = body || {};

  try {
    // 1. Health
    if (pathname === '/health' || pathname === '' || pathname === '/') {
      return sendJson(200, { status: 'ok', timestamp: new Date().toISOString() });
    }

    // 2. Samples
    if (pathname === '/samples' && req.method === 'GET') {
      return sendJson(200, [
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
    }

    // 3. Load Sample
    if (pathname === '/load-sample' && req.method === 'POST') {
      const { sampleId, projectId } = body;
      const key = sampleId as keyof typeof SAMPLE_RAW_FILES;
      if (!SAMPLE_RAW_FILES[key]) {
        return sendJson(404, { error: `Sample scan '${sampleId}' not found.` });
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

      const parsed = detectAndParseScan(rawContent, filename, targetProjectId, scanId);
      const dedup = deduplicateFindings(parsed.findings, parsed.scannerType, scanId, targetProjectId);
      let findings = dedup.canonicalFindings;

      // Automatically execute AI triage and attack-path synthesis
      findings = await aiTriageFindings(findings);
      const paths = await aiCorrelateAndBuildAttackPaths(findings, targetProjectId, scanId);
      const remediations = generateRemediationQueue(findings, paths, targetProjectId);

      const newScan: Scan = {
        id: scanId,
        projectId: targetProjectId,
        filename,
        scannerType: parsed.scannerType as any,
        uploadedAt: new Date().toISOString(),
        totalRawFindings: dedup.rawCount,
        deduplicatedCount: dedup.deduplicatedCount,
        status: 'completed',
        statusMessage: `Completed analysis: ${findings.length} findings, ${paths.length} attack paths, ${remediations.length} remediation actions.`,
        summary: {
          critical: findings.filter(f => f.severity === 'Critical').length,
          high: findings.filter(f => f.severity === 'High').length,
          medium: findings.filter(f => f.severity === 'Medium').length,
          low: findings.filter(f => f.severity === 'Low').length,
          info: findings.filter(f => f.severity === 'Info').length,
        },
      };

      db.addScan(newScan);
      db.setFindingsForScan(scanId, findings);
      db.setAttackPathsForScan(scanId, paths);
      db.setRemediations(targetProjectId, remediations);
      db.logAudit(targetProjectId, 'SAMPLE_LOADED', `Sample dataset '${filename}' loaded & correlated (${paths.length} attack paths).`);
      return sendJson(200, {
        scan: newScan,
        deduplication: dedup,
        findingsCount: findings.length,
        attackPathsCount: paths.length,
        remediationsCount: remediations.length,
        rawContent,
      });
    }

    // 4. Audit Logs
    if (pathname === '/audit-logs' && req.method === 'GET') {
      const projId = getQuery('projectId');
      return sendJson(200, db.getAuditLogs(projId || undefined));
    }

    // 5. Projects Collection
    if (pathname === '/projects') {
      if (req.method === 'GET') {
        return sendJson(200, db.getProjects());
      }
      if (req.method === 'POST') {
        const { name, targetScope, authorizedBy, description } = body;
        if (!name || !targetScope) {
          return sendJson(400, { error: 'Project name and authorized target scope are required.' });
        }
        const project = db.createProject({ name, targetScope, authorizedBy, description: description || '' });
        return sendJson(200, project);
      }
    }

    // 7. Match /projects/:projectId(/...)
    const projectMatch = pathname.match(/^\/projects\/([^\/]+)(.*)$/);
    if (projectMatch) {
      const projectId = projectMatch[1];
      const subpath = projectMatch[2];

      // Single project operations: /projects/:projectId
      if (!subpath || subpath === '/') {
        if (req.method === 'GET') {
          const p = db.getProject(projectId);
          if (!p) return sendJson(404, { error: 'Project not found.' });
          return sendJson(200, p);
        }
        if (req.method === 'DELETE') {
          const success = db.deleteProject(projectId);
          if (!success) return sendJson(404, { error: 'Project not found.' });
          return sendJson(200, { success: true });
        }
      }

      // /projects/:projectId/dashboard
      if (subpath === '/dashboard' && req.method === 'GET') {
        return sendJson(200, db.getDashboardMetrics(projectId));
      }

      // /projects/:projectId/report
      if (subpath === '/report' && req.method === 'GET') {
        const project = db.getProject(projectId);
        if (!project) return sendJson(404, { error: 'Project not found.' });

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

        return sendJson(200, report);
      }

      // /projects/:projectId/scans
      if (subpath === '/scans') {
        if (req.method === 'GET') {
          return sendJson(200, db.getScans(projectId));
        }
        if (req.method === 'POST') {
          const { filename, rawContent } = body;
          if (!rawContent || !filename) {
            return sendJson(400, { error: 'File content and filename are required.' });
          }
          const scanId = `SCN-${Date.now().toString(36).toUpperCase()}`;
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
          return sendJson(200, { scan: newScan, deduplication: dedup });
        }
      }

      // /projects/:projectId/scans/:scanId/process
      const processMatch = subpath.match(/^\/scans\/([^\/]+)\/process$/);
      if (processMatch && req.method === 'POST') {
        const scanId = processMatch[1];
        const scan = db.getScan(scanId);
        if (!scan) return sendJson(404, { error: 'Scan not found.' });

        let findings = db.getFindings(projectId, scanId);
        if (findings.length === 0) {
          return sendJson(400, { error: 'No findings available to process.' });
        }

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
        return sendJson(200, {
          success: true,
          findingsCount: findings.length,
          attackPathsCount: paths.length,
          remediationsCount: remediations.length,
        });
      }

      // /projects/:projectId/findings
      if (subpath === '/findings' && req.method === 'GET') {
        const scanId = getQuery('scanId');
        const severity = getQuery('severity');
        const asset = getQuery('asset');
        const status = getQuery('status');
        const search = getQuery('search');

        let findings = db.getFindings(projectId, scanId || undefined);
        if (severity) findings = findings.filter(f => f.severity.toLowerCase() === severity.toLowerCase());
        if (asset) findings = findings.filter(f => f.asset.toLowerCase().includes(asset.toLowerCase()));
        if (status) findings = findings.filter(f => f.status === status);
        if (search) {
          const q = search.toLowerCase();
          findings = findings.filter(f =>
            f.title.toLowerCase().includes(q) ||
            f.endpoint?.toLowerCase().includes(q) ||
            f.cwe?.toLowerCase().includes(q) ||
            f.cve?.toLowerCase().includes(q) ||
            f.vulnerabilityCategory.toLowerCase().includes(q)
          );
        }
        return sendJson(200, findings);
      }

      // /projects/:projectId/findings/:id
      const findingItemMatch = subpath.match(/^\/findings\/([^\/]+)$/);
      if (findingItemMatch) {
        const findingId = findingItemMatch[1];
        if (req.method === 'GET') {
          const f = db.getFinding(findingId);
          if (!f) return sendJson(404, { error: 'Finding not found.' });
          return sendJson(200, f);
        }
        if (req.method === 'PATCH') {
          const { status } = body;
          db.updateFinding(findingId, { status });
          db.logAudit(projectId, 'FINDING_UPDATED', `Finding ${findingId} marked as ${status}`);
          return sendJson(200, db.getFinding(findingId));
        }
      }

      // /projects/:projectId/attack-paths
      if (subpath === '/attack-paths' && req.method === 'GET') {
        const scanId = getQuery('scanId');
        return sendJson(200, db.getAttackPaths(projectId, scanId || undefined));
      }

      // /projects/:projectId/remediations
      if (subpath === '/remediations' && req.method === 'GET') {
        return sendJson(200, db.getRemediations(projectId));
      }

      // /projects/:projectId/remediations/:id/ai-guide
      const aiGuideMatch = subpath.match(/^\/remediations\/([^\/]+)\/ai-guide$/);
      if (aiGuideMatch && req.method === 'POST') {
        const remId = aiGuideMatch[1];
        const items = db.getRemediations(projectId);
        const item = items.find(r => r.id === remId);
        if (!item) return sendJson(404, { error: 'Remediation item not found.' });

        const findings = db.getFindings(projectId);
        const guidance = await aiGenerateRemediationGuidance(item, findings);
        db.updateRemediation(remId, { aiGuidance: guidance });
        return sendJson(200, guidance);
      }

      // /projects/:projectId/remediations/:id
      const remItemMatch = subpath.match(/^\/remediations\/([^\/]+)$/);
      if (remItemMatch && req.method === 'PATCH') {
        const remId = remItemMatch[1];
        const { status, assignedTo } = body;
        db.updateRemediation(remId, { status, assignedTo });
        db.logAudit(projectId, 'REMEDIATION_UPDATED', `Remediation ${remId} updated (status: ${status})`);
        return sendJson(200, db.getRemediations(projectId).find(r => r.id === remId));
      }

      // /projects/:projectId/comparisons
      if (subpath === '/comparisons' && req.method === 'GET') {
        return sendJson(200, db.getComparisons(projectId));
      }

      // /projects/:projectId/compare
      if (subpath === '/compare' && req.method === 'POST') {
        const { scan1Id, scan2Id } = body;
        const scan1 = db.getScan(scan1Id);
        const scan2 = db.getScan(scan2Id);
        if (!scan1 || !scan2) {
          return sendJson(400, { error: 'Both baseline and comparison scans must exist.' });
        }
        const scan1Findings = db.getFindings(projectId, scan1Id);
        const scan2Findings = db.getFindings(projectId, scan2Id);
        const scan1Paths = db.getAttackPaths(projectId, scan1Id);
        const scan2Paths = db.getAttackPaths(projectId, scan2Id);

        const comparison = await compareScans(scan1, scan1Findings, scan1Paths, scan2, scan2Findings, scan2Paths);
        db.addComparison(comparison);
        db.logAudit(projectId, 'SCANS_COMPARED', `Compared ${scan1.filename} with ${scan2.filename}. Eliminated ${comparison.eliminatedPathIds.length} attack paths.`);
        return sendJson(200, comparison);
      }
    }

    return sendJson(404, { error: `Not found: ${req.method} ${req.url}` });
  } catch (err: any) {
    console.error('API Handler Error:', err);
    return sendJson(500, { error: err.message || 'Internal Server Error' });
  }
}

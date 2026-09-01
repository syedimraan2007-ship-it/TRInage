import { getProject, getScans, updateScan, getFindings, setFindingsForScan, setAttackPathsForScan, setRemediations, getRuntimeStore } from '../../../../../lib/vercel-store';
import { aiTriageFindings, aiCorrelateAndBuildAttackPaths } from '../../../../../server/services/gemini';
import { generateRemediationQueue } from '../../../../../server/services/remediationEngine';

export default async function handler(req: any, res: any) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const rawProjectId = Array.isArray(req.query.projectId) ? req.query.projectId[0] : req.query.projectId;
  const rawScanId = Array.isArray(req.query.scanId) ? req.query.scanId[0] : req.query.scanId;
  const projectId = rawProjectId || '';
  const scanId = rawScanId || '';

  const project = getProject(projectId);
  if (!project) {
    return res.status(404).json({ error: 'Project not found.' });
  }

  const scans = getScans(projectId);
  const scan = scans.find((s: any) => s.id === scanId);
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found.' });
  }

  let findings = getFindings(projectId, scanId);
  if (findings.length === 0) {
    return res.status(400).json({ error: 'No findings available to process.' });
  }

  try {
    // Step 1: AI Triage
    updateScan(scanId, { status: 'analyzing', statusMessage: 'Performing contextual AI triage & evidence analysis...' });
    findings = await aiTriageFindings(findings);
    setFindingsForScan(scanId, findings);

    // Step 2: Correlate & Build Attack Paths
    updateScan(scanId, { status: 'correlating', statusMessage: 'Synthesizing multi-stage attack paths & privilege chains...' });
    const paths = await aiCorrelateAndBuildAttackPaths(findings, projectId, scanId);
    setAttackPathsForScan(scanId, paths);

    // Step 3: Prioritize Remediations
    updateScan(scanId, { status: 'building_paths', statusMessage: 'Calculating high-leverage remediation priorities...' });
    const remediations = generateRemediationQueue(findings, paths, projectId);
    setRemediations(projectId, remediations);

    // Step 4: Finalize
    updateScan(scanId, {
      status: 'completed',
      statusMessage: `Completed analysis: ${findings.length} findings, ${paths.length} attack paths, ${remediations.length} remediation actions.`,
      summary: {
        critical: findings.filter((f: any) => f.severity === 'Critical').length,
        high: findings.filter((f: any) => f.severity === 'High').length,
        medium: findings.filter((f: any) => f.severity === 'Medium').length,
        low: findings.filter((f: any) => f.severity === 'Low').length,
        info: findings.filter((f: any) => f.severity === 'Info').length,
      },
    });

    const store = getRuntimeStore();
    store.auditLogs.unshift({
      id: `LOG-${Date.now()}`,
      timestamp: new Date().toISOString(),
      action: 'ANALYSIS_COMPLETED',
      details: `AI Pipeline completed for scan ${scan.filename}: ${paths.length} attack paths prioritized.`,
      projectId,
    });

    return res.status(200).json({
      success: true,
      findingsCount: findings.length,
      attackPathsCount: paths.length,
      remediationsCount: remediations.length,
    });
  } catch (err: any) {
    updateScan(scanId, { status: 'failed', statusMessage: `Processing error: ${err.message}` });
    return res.status(500).json({ error: err.message });
  }
}

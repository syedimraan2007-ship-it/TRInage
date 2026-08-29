import { getProject, getDashboardMetrics, getAttackPaths, getRemediations, getFindings, getScans } from '../../../lib/vercel-store';

export default async function handler(req: any, res: any) {
  const rawProjectId = Array.isArray(req.query.projectId) ? req.query.projectId[0] : req.query.projectId;
  const projectId = rawProjectId || '';

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const project = getProject(projectId);
  if (!project) {
    return res.status(404).json({ error: 'Project not found.' });
  }

  const scans = getScans(projectId);
  const latestScan = scans[scans.length - 1] || { id: 'N/A', filename: 'None' };
  const metrics = getDashboardMetrics(projectId);
  const paths = getAttackPaths(projectId);
  const remediations = getRemediations(projectId);
  const findings = getFindings(projectId);

  const assetMap = new Map<string, { count: number; maxSev: string; critPaths: number }>();
  findings.forEach((finding: any) => {
    if (!assetMap.has(finding.asset)) {
      assetMap.set(finding.asset, { count: 0, maxSev: 'Low', critPaths: 0 });
    }
    const entry = assetMap.get(finding.asset)!;
    entry.count++;
    if (finding.severity === 'Critical') entry.maxSev = 'Critical';
    else if (finding.severity === 'High' && entry.maxSev !== 'Critical') entry.maxSev = 'High';
  });

  paths.forEach((path: any) => {
    if (path.severity === 'Critical') {
      path.participatingAssets.forEach((asset: string) => {
        if (assetMap.has(asset)) assetMap.get(asset)!.critPaths++;
      });
    }
  });

  const report = {
    project,
    scan: latestScan,
    metrics,
    topAttackPaths: paths.slice(0, 10),
    prioritizedRemediations: remediations.slice(0, 10),
    highRiskAssets: Array.from(assetMap.entries()).map(([asset, data]) => ({
      asset,
      findingCount: data.count,
      maxSeverity: data.maxSev,
      criticalPathsCount: data.critPaths,
    })),
    methodology: 'Normalized heterogeneous scanner ingestion, deterministic deduplication clustering, context-calibrated AI triage, graph-based attack path modeling, and deterministic mathematical risk prioritization.',
    aiLimitations: 'All AI conclusions are strictly derived from supplied scanner evidence. No unauthorized exploitation was performed. Testing is restricted to explicitly authorized assets.',
    generatedAt: new Date().toISOString(),
  };

  return res.status(200).json(report);
}

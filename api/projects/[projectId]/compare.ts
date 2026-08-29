import { getProject, getAttackPaths, getFindings, getScans } from '../../../lib/vercel-store';

export default async function handler(req: any, res: any) {
  const rawProjectId = Array.isArray(req.query.projectId) ? req.query.projectId[0] : req.query.projectId;
  const projectId = rawProjectId || '';

  if (!getProject(projectId)) {
    return res.status(404).json({ error: 'Project not found.' });
  }

  if (req.method === 'POST') {
    const { scan1Id, scan2Id } = req.body || {};
    const scan1 = getScans(projectId).find((scan: any) => scan.id === scan1Id);
    const scan2 = getScans(projectId).find((scan: any) => scan.id === scan2Id);

    if (!scan1 || !scan2) {
      return res.status(400).json({ error: 'Both baseline and comparison scans must exist.' });
    }

    const scan1Findings = getFindings(projectId, scan1Id);
    const scan2Findings = getFindings(projectId, scan2Id);
    const scan1Paths = getAttackPaths(projectId, scan1Id);
    const scan2Paths = getAttackPaths(projectId, scan2Id);

    const comparison = {
      id: `CMP-${Date.now().toString(36).toUpperCase()}`,
      projectId,
      scan1Id,
      scan2Id,
      scan1Name: scan1.filename,
      scan2Name: scan2.filename,
      createdAt: new Date().toISOString(),
      resolvedFindingIds: [],
      persistentFindingIds: [...new Set([...scan1Findings.map((f: any) => f.id), ...scan2Findings.map((f: any) => f.id)])],
      newFindingIds: scan2Findings.map((f: any) => f.id).filter((id: string) => !scan1Findings.some((f: any) => f.id === id)),
      eliminatedPathIds: scan1Paths.map((p: any) => p.id).filter((id: string) => !scan2Paths.some((p: any) => p.id === id)),
      newPathIds: scan2Paths.map((p: any) => p.id).filter((id: string) => !scan1Paths.some((p: any) => p.id === id)),
      riskScoreDelta: scan2Paths.reduce((sum: number, p: any) => sum + (p.contextualScore || 0), 0) - scan1Paths.reduce((sum: number, p: any) => sum + (p.contextualScore || 0), 0),
      aiSummary: `Compared ${scan1.filename} and ${scan2.filename}.`,
    };

    const store = (globalThis as any).__ai_vuln_store__;
    if (store) {
      store.comparisons = [comparison, ...store.comparisons.filter((item: any) => item.projectId !== projectId || !(item.scan1Id === scan1Id && item.scan2Id === scan2Id))];
    }

    return res.status(200).json(comparison);
  }

  res.setHeader('Allow', 'POST');
  return res.status(405).json({ error: 'Method not allowed' });
}

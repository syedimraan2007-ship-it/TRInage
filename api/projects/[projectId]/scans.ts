import { addScan, getProject, getScans } from '../../../lib/vercel-store';
import { detectAndParseScan } from '../../../server/parsers';
import { deduplicateFindings } from '../../../server/services/deduplication';

export default async function handler(req: any, res: any) {
  const rawProjectId = Array.isArray(req.query.projectId) ? req.query.projectId[0] : req.query.projectId;
  const projectId = rawProjectId || '';

  if (!getProject(projectId)) {
    return res.status(404).json({ error: 'Project not found.' });
  }

  if (req.method === 'GET') {
    return res.status(200).json(getScans(projectId));
  }

  if (req.method === 'POST') {
    const { filename, rawContent } = req.body || {};

    if (!filename || !rawContent) {
      return res.status(400).json({ error: 'File content and filename are required.' });
    }

    const scanId = `SCN-${Date.now().toString(36).toUpperCase()}`;
    const parsed = detectAndParseScan(String(rawContent), String(filename), projectId, scanId);
    const dedup = deduplicateFindings(parsed.findings, parsed.scannerType, scanId, projectId);

    const scan = {
      id: scanId,
      projectId,
      filename: String(filename),
      scannerType: parsed.scannerType,
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

    addScan(scan);
    if (dedup.canonicalFindings.length > 0) {
      const store = (globalThis as any).__ai_vuln_store__ || { findings: [] };
      store.findings = [...store.findings.filter((finding: any) => finding.scanId !== scanId), ...dedup.canonicalFindings];
    }

    return res.status(201).json({ scan, deduplication: dedup });
  }

  res.setHeader('Allow', 'GET, POST');
  return res.status(405).json({ error: 'Method not allowed' });
}

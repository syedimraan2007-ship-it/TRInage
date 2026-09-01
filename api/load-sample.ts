import { SAMPLE_RAW_FILES } from '../server/sampleData';
import { getProjects, addScan, getRuntimeStore } from '../lib/vercel-store';
import { detectAndParseScan } from '../server/parsers';
import { deduplicateFindings } from '../server/services/deduplication';

export default async function handler(req: any, res: any) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

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
  const projects = getProjects();
  const targetProjectId = projectId || projects[0]?.id || 'PRJ-FINTECH-CORE';
  const scanId = `SCN-${Date.now().toString(36).toUpperCase()}`;

  try {
    const parsed = detectAndParseScan(rawContent, filename, targetProjectId, scanId);
    const dedup = deduplicateFindings(parsed.findings, parsed.scannerType, scanId, targetProjectId);

    const newScan = {
      id: scanId,
      projectId: targetProjectId,
      filename,
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

    addScan(newScan);
    const store = getRuntimeStore();
    store.findings = [...store.findings.filter((f: any) => f.scanId !== scanId), ...dedup.canonicalFindings];
    store.auditLogs.unshift({
      id: `LOG-${Date.now()}`,
      timestamp: new Date().toISOString(),
      action: 'SAMPLE_LOADED',
      details: `Sample dataset '${filename}' loaded.`,
      projectId: targetProjectId,
    });

    return res.status(200).json({ scan: newScan, deduplication: dedup, rawContent });
  } catch (err: any) {
    return res.status(400).json({ error: err.message });
  }
}

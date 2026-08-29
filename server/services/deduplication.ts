import { NormalizedFinding, Severity, Confidence, RawFindingSource } from '../../src/types';

export interface DeduplicationResult {
  canonicalFindings: NormalizedFinding[];
  rawCount: number;
  deduplicatedCount: number;
  duplicatesRemoved: number;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Info: 1,
};

const CONFIDENCE_ORDER: Record<Confidence, number> = {
  Confirmed: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Unknown: 1,
};

/**
 * Normalizes an endpoint/path string for fuzzy deduplication
 */
function normalizePath(endpoint?: string): string {
  if (!endpoint) return '/';
  try {
    if (endpoint.startsWith('http://') || endpoint.startsWith('https://')) {
      const u = new URL(endpoint);
      return u.pathname.replace(/\/+/g, '/').toLowerCase();
    }
  } catch {}
  return endpoint.split('?')[0].replace(/\/+/g, '/').toLowerCase().trim();
}

/**
 * Normalizes vulnerability category/title for clustering
 */
function normalizeCategory(cat?: string, title?: string, cwe?: string): string {
  if (cwe && cwe.trim()) return cwe.toUpperCase().trim();
  const text = `${cat || ''} ${title || ''}`.toLowerCase();
  if (text.includes('sql injection') || text.includes('sqli')) return 'CWE-89: SQL Injection';
  if (text.includes('cross-site scripting') || text.includes('xss')) return 'CWE-79: XSS';
  if (text.includes('server-side request forgery') || text.includes('ssrf')) return 'CWE-918: SSRF';
  if (text.includes('remote code execution') || text.includes('rce') || text.includes('command injection')) return 'CWE-78: OS Command Injection';
  if (text.includes('idor') || text.includes('insecure direct object') || text.includes('broken object level')) return 'CWE-639: IDOR';
  if (text.includes('jwt') || text.includes('token') || text.includes('broken authentication')) return 'CWE-287: Broken Authentication';
  if (text.includes('directory traversal') || text.includes('path traversal') || text.includes('lfi')) return 'CWE-22: Path Traversal';
  if (text.includes('hardcoded') || text.includes('secret') || text.includes('api key leak')) return 'CWE-798: Hardcoded Credentials';
  if (text.includes('csrf') || text.includes('cross-site request')) return 'CWE-352: CSRF';
  if (text.includes('open port') || text.includes('exposed service')) return 'CWE-200: Information Exposure';
  return cat || title || 'Vulnerability';
}

/**
 * Deterministically deduplicates raw scanner findings while preserving complete provenance.
 */
export function deduplicateFindings(
  rawFindings: Partial<NormalizedFinding>[],
  scannerType: string,
  scanId: string,
  projectId: string
): DeduplicationResult {
  const groups = new Map<string, Partial<NormalizedFinding>[]>();

  rawFindings.forEach((f, idx) => {
    const assetKey = (f.asset || f.hostname || f.ip || 'target').toLowerCase().trim();
    const endpointKey = normalizePath(f.endpoint);
    const catKey = normalizeCategory(f.vulnerabilityCategory, f.title, f.cwe);
    const paramKey = (f.parameter || f.affectedComponent || '').toLowerCase().trim();

    // Fingerprint signature for deduplication
    const groupKey = `${assetKey}::${endpointKey}::${catKey}::${paramKey}`;

    if (!groups.has(groupKey)) {
      groups.set(groupKey, []);
    }
    // Tag internal rawSourceId if not present
    f.projectId = projectId;
    f.scanId = scanId;
    groups.get(groupKey)!.push(f);
  });

  const canonicalFindings: NormalizedFinding[] = [];

  let indexCounter = 1;
  for (const [groupKey, items] of groups.entries()) {
    // Pick the most severe / highest confidence item as representative
    items.sort((a, b) => {
      const sevDiff = (SEVERITY_ORDER[b.severity || 'Medium'] || 3) - (SEVERITY_ORDER[a.severity || 'Medium'] || 3);
      if (sevDiff !== 0) return sevDiff;
      return (CONFIDENCE_ORDER[b.confidence || 'Medium'] || 3) - (CONFIDENCE_ORDER[a.confidence || 'Medium'] || 3);
    });

    const primary = items[0];
    const findingId = `FND-${scanId.slice(-6)}-${String(indexCounter++).padStart(3, '0')}`;
    const dedupGroupId = `DEDUP-${Buffer.from(groupKey).toString('base64').slice(0, 12)}`;

    // Build complete provenance records
    const provenance: RawFindingSource[] = items.map((it, i) => ({
      scanner: it.affectedComponent?.includes('Plugin') ? 'OWASP ZAP' : scannerType.toUpperCase(),
      scannerFindingId: `RAW-${idxHash(groupKey, i)}`,
      rawJson: JSON.stringify({
        title: it.title,
        severity: it.severity,
        endpoint: it.endpoint,
        param: it.parameter,
        evidence: it.evidence,
      }),
      timestamp: new Date().toISOString(),
      scanId,
    }));

    // Merge evidence if available across duplicates
    const aggregatedEvidence = { ...primary.evidence };
    for (const it of items) {
      if (it.evidence?.request && !aggregatedEvidence.request) aggregatedEvidence.request = it.evidence.request;
      if (it.evidence?.response && !aggregatedEvidence.response) aggregatedEvidence.response = it.evidence.response;
      if (it.evidence?.payload && !aggregatedEvidence.payload) aggregatedEvidence.payload = it.evidence.payload;
      if (it.evidence?.rawOutput && !aggregatedEvidence.rawOutput) aggregatedEvidence.rawOutput = it.evidence.rawOutput;
    }

    const canonical: NormalizedFinding = {
      id: findingId,
      scanId,
      projectId,
      title: primary.title || 'Identified Security Weakness',
      vulnerabilityCategory: primary.vulnerabilityCategory || 'Security Finding',
      cwe: primary.cwe,
      cve: primary.cve,
      severity: primary.severity || 'Medium',
      confidence: primary.confidence || 'High',
      asset: primary.asset || 'Primary Asset',
      hostname: primary.hostname,
      ip: primary.ip,
      port: primary.port,
      protocol: primary.protocol,
      service: primary.service,
      technology: primary.technology,
      endpoint: primary.endpoint || '/',
      httpMethod: primary.httpMethod,
      parameter: primary.parameter,
      affectedComponent: primary.affectedComponent,
      evidence: aggregatedEvidence,
      description: primary.description || '',
      authContext: primary.authContext || 'Unauthenticated',
      privilegeContext: primary.privilegeContext,
      dataSensitivity: primary.dataSensitivity || 'Internal',
      status: 'open',
      dedupGroupId,
      sourceCount: items.length,
      provenance,
      createdAt: new Date().toISOString(),
    };

    canonicalFindings.push(canonical);
  }

  return {
    canonicalFindings,
    rawCount: rawFindings.length,
    deduplicatedCount: canonicalFindings.length,
    duplicatesRemoved: rawFindings.length - canonicalFindings.length,
  };
}

function idxHash(str: string, index: number): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash).toString(16).slice(0, 6) + '-' + index;
}

import { NormalizedFinding, Severity, Confidence, RawFindingSource } from '../../src/types';

/**
 * Sanitizes untrusted text from security scans to prevent prompt injection or code injection.
 */
export function sanitizeUntrustedText(text?: string, maxLen = 3000): string {
  if (!text || typeof text !== 'string') return '';
  // Strip control chars except standard whitespace
  const sanitized = text
    .replace(/[\u0000-\u0008\u000B-\u000C\u000E-\u001F\u007F-\u009F]/g, '')
    .trim();
  return sanitized.length > maxLen ? sanitized.slice(0, maxLen) + '...[truncated]' : sanitized;
}

export function mapSeverity(raw?: string): Severity {
  if (!raw) return 'Medium';
  const lower = String(raw).toLowerCase().trim();
  if (lower.includes('crit') || lower === '4' || lower === 'urgent') return 'Critical';
  if (lower.includes('high') || lower === '3' || lower === 'error') return 'High';
  if (lower.includes('med') || lower === '2' || lower === 'warning') return 'Medium';
  if (lower.includes('low') || lower === '1') return 'Low';
  if (lower.includes('info') || lower.includes('note') || lower === '0') return 'Info';
  return 'Medium';
}

export function mapConfidence(raw?: string): Confidence {
  if (!raw) return 'Medium';
  const lower = String(raw).toLowerCase().trim();
  if (lower.includes('confirm') || lower.includes('certain') || lower === '3') return 'Confirmed';
  if (lower.includes('high') || lower === '2') return 'High';
  if (lower.includes('med') || lower === '1') return 'Medium';
  if (lower.includes('low') || lower.includes('tentative') || lower.includes('suspect')) return 'Low';
  return 'Medium';
}

export function parseZapReport(data: any, projectId: string, scanId: string): Partial<NormalizedFinding>[] {
  const findings: Partial<NormalizedFinding>[] = [];
  const sites = Array.isArray(data?.site) ? data.site : data?.site ? [data.site] : [];

  for (const site of sites) {
    const host = site['@host'] || site['host'] || site['@name'] || 'unknown-host';
    const alerts = Array.isArray(site.alerts) ? site.alerts : Array.isArray(site.alert) ? site.alert : [];

    for (const alert of alerts) {
      const instances = Array.isArray(alert.instances) ? alert.instances : Array.isArray(alert.instance) ? alert.instance : [];
      const firstInstance = instances[0] || {};
      const uri = firstInstance.uri || alert.uri || `https://${host}`;
      let path = '';
      try {
        const u = new URL(uri);
        path = u.pathname + u.search;
      } catch {
        path = uri;
      }

      findings.push({
        projectId,
        scanId,
        title: sanitizeUntrustedText(alert.name || alert.alert || 'ZAP Security Alert'),
        vulnerabilityCategory: sanitizeUntrustedText(alert.name || 'Web Vulnerability'),
        cwe: alert.cweid ? `CWE-${alert.cweid}` : undefined,
        cve: alert.cveid || undefined,
        severity: mapSeverity(alert.riskdesc || alert.riskcode || alert.confidence),
        confidence: mapConfidence(alert.confidence),
        asset: host,
        hostname: host,
        endpoint: path || '/',
        httpMethod: firstInstance.method || alert.method || 'GET',
        parameter: firstInstance.param || alert.param || undefined,
        description: sanitizeUntrustedText(alert.desc || alert.description || ''),
        affectedComponent: alert.pluginId ? `Plugin-${alert.pluginId}` : undefined,
        evidence: {
          request: sanitizeUntrustedText(firstInstance.evidence || firstInstance.attack || ''),
          response: sanitizeUntrustedText(firstInstance.otherinfo || ''),
          payload: sanitizeUntrustedText(firstInstance.attack || ''),
        },
        authContext: 'Unauthenticated',
        dataSensitivity: 'Internal',
      });
    }
  }
  return findings;
}

export function parseNucleiReport(items: any[], projectId: string, scanId: string): Partial<NormalizedFinding>[] {
  const findings: Partial<NormalizedFinding>[] = [];

  for (const item of items) {
    if (!item || typeof item !== 'object') continue;
    const info = item.info || {};
    const host = item.host || item['matched-at'] || item.ip || 'unknown-asset';
    let assetClean = host;
    try {
      if (host.startsWith('http')) {
        const u = new URL(host);
        assetClean = u.host;
      }
    } catch {}

    const cve = Array.isArray(info.classification?.['cve-id']) 
      ? info.classification['cve-id'].join(', ') 
      : info.classification?.['cve-id'] || undefined;
    const cwe = Array.isArray(info.classification?.['cwe-id']) 
      ? info.classification['cwe-id'].join(', ') 
      : info.classification?.['cwe-id'] || undefined;

    findings.push({
      projectId,
      scanId,
      title: sanitizeUntrustedText(info.name || item['template-id'] || 'Nuclei Finding'),
      vulnerabilityCategory: sanitizeUntrustedText(info.name || item.type || 'Vulnerability'),
      cwe: cwe ? (cwe.toUpperCase().startsWith('CWE') ? cwe : `CWE-${cwe}`) : undefined,
      cve: cve || undefined,
      severity: mapSeverity(info.severity || item.severity),
      confidence: item['extracted-results'] || item['matcher-status'] ? 'Confirmed' : 'High',
      asset: assetClean,
      hostname: assetClean,
      ip: item.ip || undefined,
      endpoint: item['matched-at'] || item.url || '/',
      httpMethod: item.type === 'http' ? 'GET/POST' : undefined,
      protocol: item.type || 'http',
      description: sanitizeUntrustedText(info.description || info.reference?.join('\n') || ''),
      affectedComponent: item['template-id'] || undefined,
      evidence: {
        rawOutput: sanitizeUntrustedText(item['curl-command'] || JSON.stringify(item['extracted-results'] || '')),
        payload: sanitizeUntrustedText(Array.isArray(item['extracted-results']) ? item['extracted-results'].join(', ') : item['extracted-results']),
      },
      authContext: 'Unauthenticated',
      dataSensitivity: 'Internal',
    });
  }
  return findings;
}

export function parseSemgrepReport(data: any, projectId: string, scanId: string): Partial<NormalizedFinding>[] {
  const findings: Partial<NormalizedFinding>[] = [];
  const results = Array.isArray(data?.results) ? data.results : [];

  for (const item of results) {
    const meta = item.extra?.metadata || {};
    const cwe = Array.isArray(meta.cwe) ? meta.cwe.join(', ') : meta.cwe;
    const cve = Array.isArray(meta.cve) ? meta.cve.join(', ') : meta.cve;
    const path = item.path || 'src';

    findings.push({
      projectId,
      scanId,
      title: sanitizeUntrustedText(meta.shortDescription || item.check_id?.split('.').pop() || item.check_id || 'Semgrep Code Defect'),
      vulnerabilityCategory: sanitizeUntrustedText(meta.category || meta.owasp || 'Source Code Vulnerability'),
      cwe: cwe ? (cwe.toUpperCase().startsWith('CWE') ? cwe : `CWE-${cwe}`) : undefined,
      cve: cve || undefined,
      severity: mapSeverity(item.extra?.severity || meta.impact),
      confidence: mapConfidence(meta.confidence || 'High'),
      asset: 'Source Codebase',
      endpoint: `${path}:${item.start?.line || 1}`,
      affectedComponent: path,
      description: sanitizeUntrustedText(item.extra?.message || meta.description || ''),
      evidence: {
        rawOutput: sanitizeUntrustedText(item.extra?.lines || ''),
        matchedPattern: item.check_id,
      },
      authContext: 'Low Privilege',
      dataSensitivity: 'Internal',
    });
  }
  return findings;
}

export function parseTrivyReport(data: any, projectId: string, scanId: string): Partial<NormalizedFinding>[] {
  const findings: Partial<NormalizedFinding>[] = [];
  const results = Array.isArray(data?.Results) ? data.Results : [];
  const artifactName = data?.ArtifactName || 'container-image';

  for (const res of results) {
    const target = res.Target || artifactName;
    const vulns = Array.isArray(res.Vulnerabilities) ? res.Vulnerabilities : [];

    for (const vuln of vulns) {
      findings.push({
        projectId,
        scanId,
        title: sanitizeUntrustedText(`${vuln.VulnerabilityID || 'Vulnerability'} in ${vuln.PkgName || 'Package'}`),
        vulnerabilityCategory: 'Dependency / Package Vulnerability',
        cve: vuln.VulnerabilityID?.startsWith('CVE') ? vuln.VulnerabilityID : undefined,
        cwe: vuln.CweIDs ? vuln.CweIDs.join(', ') : undefined,
        severity: mapSeverity(vuln.Severity),
        confidence: 'Confirmed',
        asset: target,
        endpoint: vuln.PkgName,
        affectedComponent: `${vuln.PkgName} (${vuln.InstalledVersion}) -> Fixed: ${vuln.FixedVersion || 'No Fix'}`,
        description: sanitizeUntrustedText(vuln.Title || vuln.Description || ''),
        evidence: {
          rawOutput: `Installed: ${vuln.InstalledVersion} | Fixed in: ${vuln.FixedVersion || 'N/A'} | Link: ${vuln.PrimaryURL || ''}`,
        },
        authContext: 'Internal Service',
        dataSensitivity: 'Internal',
      });
    }
  }
  return findings;
}

export function parseNmapReport(data: any, projectId: string, scanId: string): Partial<NormalizedFinding>[] {
  const findings: Partial<NormalizedFinding>[] = [];
  const hosts = Array.isArray(data?.hosts) ? data.hosts : Array.isArray(data?.nmaprun?.host) ? data.nmaprun.host : data?.host ? [data.host] : [];

  for (const host of hosts) {
    const address = host.address?.['@addr'] || host.address?.addr || host.ip || host.hostname || '127.0.0.1';
    const hostnames = host.hostnames?.hostname || host.hostname || address;
    const ports = Array.isArray(host.ports?.port) ? host.ports.port : host.ports ? [host.ports] : [];

    for (const p of ports) {
      const portId = parseInt(p['@portid'] || p.portid || p.port || '0', 10);
      const serviceName = p.service?.['@name'] || p.service?.name || p.service || 'unknown';
      const state = p.state?.['@state'] || p.state?.state || p.state || 'open';
      const scripts = Array.isArray(p.script) ? p.script : p.script ? [p.script] : [];

      if (scripts.length > 0) {
        for (const scr of scripts) {
          findings.push({
            projectId,
            scanId,
            title: sanitizeUntrustedText(`Service Vulnerability: ${scr['@id'] || scr.id || scr.name} on port ${portId}/${serviceName}`),
            vulnerabilityCategory: 'Network / Exposed Service Vulnerability',
            severity: mapSeverity(scr.output?.includes('VULNERABLE') ? 'High' : 'Medium'),
            confidence: 'Confirmed',
            asset: String(hostnames),
            ip: String(address),
            port: portId,
            service: serviceName,
            endpoint: `:${portId}`,
            description: sanitizeUntrustedText(scr['@output'] || scr.output || `Script ${scr.id} executed on ${serviceName}`),
            evidence: {
              rawOutput: sanitizeUntrustedText(scr['@output'] || scr.output || ''),
            },
            authContext: 'Unauthenticated',
          });
        }
      } else if (state === 'open' && (portId === 21 || portId === 23 || portId === 3389 || portId === 3306 || portId === 5432 || portId === 27017 || portId === 6379 || portId === 9200)) {
        findings.push({
          projectId,
          scanId,
          title: `Exposed Sensitive Service: ${serviceName.toUpperCase()} on Port ${portId}`,
          vulnerabilityCategory: 'Unrestricted Network Exposure',
          severity: 'High',
          confidence: 'Confirmed',
          asset: String(hostnames),
          ip: String(address),
          port: portId,
          service: serviceName,
          endpoint: `:${portId}`,
          description: `Sensitive backend service (${serviceName}) exposed directly to network interface.`,
          evidence: {
            rawOutput: `Port ${portId}/tcp ${state} ${serviceName}`,
          },
          authContext: 'Unauthenticated',
        });
      }
    }
  }
  return findings;
}

export function parseGenericCsv(csvText: string, projectId: string, scanId: string): Partial<NormalizedFinding>[] {
  const lines = csvText.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  if (lines.length < 2) return [];

  // Parse CSV header
  const headers = parseCsvRow(lines[0]).map(h => h.toLowerCase().replace(/[^a-z0-9]/g, ''));
  const findings: Partial<NormalizedFinding>[] = [];

  const titleIdx = headers.findIndex(h => h.includes('title') || h.includes('name') || h.includes('alert') || h.includes('vuln'));
  const severityIdx = headers.findIndex(h => h.includes('sev') || h.includes('risk') || h.includes('priority'));
  const assetIdx = headers.findIndex(h => h.includes('asset') || h.includes('host') || h.includes('target') || h.includes('url'));
  const endpointIdx = headers.findIndex(h => h.includes('end') || h.includes('path') || h.includes('uri') || h.includes('loc'));
  const cveIdx = headers.findIndex(h => h.includes('cve'));
  const cweIdx = headers.findIndex(h => h.includes('cwe'));
  const descIdx = headers.findIndex(h => h.includes('desc') || h.includes('detail') || h.includes('summary'));
  const evidenceIdx = headers.findIndex(h => h.includes('evi') || h.includes('payload') || h.includes('proof'));
  const catIdx = headers.findIndex(h => h.includes('cat') || h.includes('type'));

  for (let i = 1; i < lines.length; i++) {
    const row = parseCsvRow(lines[i]);
    if (!row || row.length === 0) continue;

    const title = titleIdx !== -1 ? row[titleIdx] : row[0] || `Finding-${i}`;
    const severity = severityIdx !== -1 ? row[severityIdx] : 'Medium';
    const asset = assetIdx !== -1 ? row[assetIdx] : 'Target Asset';
    const endpoint = endpointIdx !== -1 ? row[endpointIdx] : '/';
    const cve = cveIdx !== -1 ? row[cveIdx] : undefined;
    const cwe = cweIdx !== -1 ? row[cweIdx] : undefined;
    const desc = descIdx !== -1 ? row[descIdx] : '';
    const evidence = evidenceIdx !== -1 ? row[evidenceIdx] : '';
    const category = catIdx !== -1 ? row[catIdx] : 'Security Finding';

    if (!title) continue;

    findings.push({
      projectId,
      scanId,
      title: sanitizeUntrustedText(title),
      vulnerabilityCategory: sanitizeUntrustedText(category),
      severity: mapSeverity(severity),
      confidence: 'High',
      asset: sanitizeUntrustedText(asset || 'App Server'),
      endpoint: sanitizeUntrustedText(endpoint || '/'),
      cve: cve ? sanitizeUntrustedText(cve) : undefined,
      cwe: cwe ? sanitizeUntrustedText(cwe) : undefined,
      description: sanitizeUntrustedText(desc),
      evidence: evidence ? { rawOutput: sanitizeUntrustedText(evidence) } : undefined,
      status: 'open',
      authContext: 'Unauthenticated',
      dataSensitivity: 'Internal',
    });
  }

  return findings;
}

function parseCsvRow(rowText: string): string[] {
  const res: string[] = [];
  let inQuotes = false;
  let cur = '';

  for (let i = 0; i < rowText.length; i++) {
    const ch = rowText[i];
    if (ch === '"') {
      if (inQuotes && rowText[i + 1] === '"') {
        cur += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      res.push(cur.trim());
      cur = '';
    } else {
      cur += ch;
    }
  }
  res.push(cur.trim());
  return res;
}

export function parseGenericJson(jsonData: any, projectId: string, scanId: string): Partial<NormalizedFinding>[] {
  const items = Array.isArray(jsonData) 
    ? jsonData 
    : Array.isArray(jsonData?.findings) 
    ? jsonData.findings 
    : Array.isArray(jsonData?.vulnerabilities) 
    ? jsonData.vulnerabilities 
    : Array.isArray(jsonData?.issues) 
    ? jsonData.issues 
    : Array.isArray(jsonData?.items) 
    ? jsonData.items 
    : [jsonData];

  const findings: Partial<NormalizedFinding>[] = [];

  for (const item of items) {
    if (!item || typeof item !== 'object') continue;

    const title = item.title || item.name || item.vulnerability || item.alert || item.ruleId || 'Security Finding';
    const asset = item.asset || item.host || item.target || item.hostname || item.ip || item.server || 'Primary Target';
    const endpoint = item.endpoint || item.path || item.uri || item.url || item.location || '/';
    const severity = mapSeverity(item.severity || item.risk || item.level || item.impact);
    const confidence = mapConfidence(item.confidence || item.status || 'High');
    const category = item.category || item.type || item.vulnerabilityCategory || 'General Security Weakness';
    const cve = item.cve || item.cveId || item.cve_id || undefined;
    const cwe = item.cwe || item.cweId || item.cwe_id || undefined;
    const desc = item.description || item.desc || item.details || item.message || '';
    const evidenceRaw = item.evidence || item.proof || item.rawOutput || item.payload || '';

    findings.push({
      projectId,
      scanId,
      title: sanitizeUntrustedText(title),
      vulnerabilityCategory: sanitizeUntrustedText(category),
      severity,
      confidence,
      asset: sanitizeUntrustedText(asset),
      endpoint: sanitizeUntrustedText(endpoint),
      cve: cve ? sanitizeUntrustedText(cve) : undefined,
      cwe: cwe ? sanitizeUntrustedText(cwe) : undefined,
      description: sanitizeUntrustedText(desc),
      evidence: typeof evidenceRaw === 'object' ? evidenceRaw : { rawOutput: sanitizeUntrustedText(String(evidenceRaw)) },
      authContext: item.authContext || 'Unauthenticated',
      dataSensitivity: item.dataSensitivity || 'Internal',
      status: 'open',
    });
  }

  return findings;
}

export function detectAndParseScan(
  content: string,
  filename: string,
  projectId: string,
  scanId: string
): { scannerType: string; findings: Partial<NormalizedFinding>[] } {
  const cleanContent = content.trim();

  // Try JSON
  if (cleanContent.startsWith('{') || cleanContent.startsWith('[')) {
    try {
      const parsed = JSON.parse(cleanContent);

      // 1. ZAP detection
      if (parsed.site || parsed['@generated'] || parsed.OWASPZAPReport) {
        const zapData = parsed.OWASPZAPReport || parsed;
        return { scannerType: 'zap', findings: parseZapReport(zapData, projectId, scanId) };
      }

      // 2. Nuclei detection
      if (Array.isArray(parsed) && parsed[0]?.['template-id']) {
        return { scannerType: 'nuclei', findings: parseNucleiReport(parsed, projectId, scanId) };
      }

      // 3. Semgrep detection
      if (parsed.results && (parsed.version || parsed.paths)) {
        return { scannerType: 'semgrep', findings: parseSemgrepReport(parsed, projectId, scanId) };
      }

      // 4. Trivy detection
      if (parsed.ArtifactName || (parsed.Results && Array.isArray(parsed.Results))) {
        return { scannerType: 'trivy', findings: parseTrivyReport(parsed, projectId, scanId) };
      }

      // 5. Nmap detection
      if (parsed.nmaprun || parsed.hosts || (parsed.host && parsed.ports)) {
        return { scannerType: 'nmap', findings: parseNmapReport(parsed, projectId, scanId) };
      }

      // 6. Generic JSON
      return { scannerType: 'generic_json', findings: parseGenericJson(parsed, projectId, scanId) };
    } catch {
      // Check for JSON-Lines (NDJSON like Nuclei output)
      const lines = cleanContent.split('\n').filter(Boolean);
      const validObjects: any[] = [];
      for (const line of lines) {
        try {
          const obj = JSON.parse(line);
          if (obj && typeof obj === 'object') validObjects.push(obj);
        } catch {}
      }
      if (validObjects.length > 0 && validObjects[0]?.['template-id']) {
        return { scannerType: 'nuclei', findings: parseNucleiReport(validObjects, projectId, scanId) };
      }
      if (validObjects.length > 0) {
        return { scannerType: 'generic_json', findings: parseGenericJson(validObjects, projectId, scanId) };
      }
    }
  }

  // Try CSV
  if (filename.endsWith('.csv') || cleanContent.includes(',')) {
    const findings = parseGenericCsv(cleanContent, projectId, scanId);
    if (findings.length > 0) {
      return { scannerType: 'generic_csv', findings };
    }
  }

  throw new Error('Unsupported or malformed scan format. Please provide valid ZAP, Nuclei, Semgrep, Trivy, Nmap, Generic JSON or CSV format.');
}

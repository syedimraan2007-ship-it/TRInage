export default async function handler(req: any, res: any) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  return res.status(200).json([
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

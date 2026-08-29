import { AttackPath, NormalizedFinding, RemediationItem, RemediationPriority } from '../../src/types';

export function generateRemediationQueue(
  findings: NormalizedFinding[],
  attackPaths: AttackPath[],
  projectId: string
): RemediationItem[] {
  // Map finding -> affected attack paths
  const findingToPaths = new Map<string, string[]>();
  attackPaths.forEach(p => {
    p.participatingFindingIds.forEach(fid => {
      if (!findingToPaths.has(fid)) {
        findingToPaths.set(fid, []);
      }
      findingToPaths.get(fid)!.push(p.id);
    });
  });

  // Group findings into logical remediation themes
  const remediationGroups = new Map<string, {
    title: string;
    action: string;
    findingIds: string[];
    safeguards: string[];
  }>();

  findings.forEach(f => {
    const cat = (f.vulnerabilityCategory + ' ' + f.title).toLowerCase();
    let groupKey = 'general';
    let groupTitle = `Remediate ${f.title}`;
    let action = `Apply secure coding standards and input sanitization to ${f.endpoint} on ${f.asset}.`;
    let safeguards = ['Input validation', 'Least privilege'];

    if (cat.includes('sql') || cat.includes('sqli')) {
      groupKey = `sqli-${f.asset}`;
      groupTitle = `Enforce Parameterized SQL Queries & Prepared Statements on ${f.asset}`;
      action = `Refactor dynamic SQL queries on ${f.endpoint} to use parameterized queries/ORM with strict query parameter typing.`;
      safeguards = ['Prepared Statements / Parameterized Queries', 'Database user principle of least privilege', 'WAF SQLi rule inspection'];
    } else if (cat.includes('ssrf')) {
      groupKey = `ssrf-${f.asset}`;
      groupTitle = `Harden Outbound HTTP Requests & Network Egress on ${f.asset}`;
      action = `Implement strict destination allowlisting, block RFC1918/link-local IP addresses (169.254.169.254), and disable HTTP redirects on ${f.endpoint}.`;
      safeguards = ['Egress IP/Domain Allowlisting', 'Block cloud metadata endpoint (169.254.169.254)', 'Isolated outbound proxy'];
    } else if (cat.includes('jwt') || cat.includes('auth') || cat.includes('token') || cat.includes('session')) {
      groupKey = `auth-${f.asset}`;
      groupTitle = `Enforce Cryptographic Token Verification & Auth Middleware on ${f.asset}`;
      action = `Verify asymmetric JWT signatures (RS256) and reject unsigned / "none" algorithm tokens at the API gateway layer.`;
      safeguards = ['Strict RS256 algorithm enforcement', 'Mandatory expiration and audience claim checks', 'Centralized auth middleware'];
    } else if (cat.includes('idor') || cat.includes('access control') || cat.includes('broken object')) {
      groupKey = `idor-${f.asset}`;
      groupTitle = `Implement Object-Level Authorization Checks on ${f.asset}`;
      action = `Verify that the authenticated tenant owns the requested resource ID before executing database operations on ${f.endpoint}.`;
      safeguards = ['Tenant isolation middleware', 'Context-aware RBAC/ABAC policy checks'];
    } else if (cat.includes('secret') || cat.includes('hardcoded') || cat.includes('credential')) {
      groupKey = `secrets-${f.asset}`;
      groupTitle = `Rotate Exposed Credentials & Migrate to Secrets Manager on ${f.asset}`;
      action = `Immediately revoke exposed credentials, rotate API keys, and migrate configurations to a secure key vault/secrets manager.`;
      safeguards = ['Automated secret rotation', 'Environment secret injection', 'Static code secret scanning'];
    } else if (cat.includes('xss') || cat.includes('cross-site')) {
      groupKey = `xss-${f.asset}`;
      groupTitle = `Apply Context-Aware Contextual Output Encoding & CSP on ${f.asset}`;
      action = `Sanitize and encode all untrusted user reflections in ${f.endpoint} and deploy a restrictive Content-Security-Policy (CSP) header.`;
      safeguards = ['Contextual HTML/JS output encoding', 'Strict Content-Security-Policy', 'HttpOnly cookie flags'];
    } else if (cat.includes('package') || cat.includes('dependency') || cat.includes('cve')) {
      groupKey = `deps-${f.asset}`;
      groupTitle = `Upgrade Vulnerable Dependencies & Packages on ${f.asset}`;
      action = `Update ${f.affectedComponent || 'vulnerable packages'} to patched upstream versions to eliminate known CVEs.`;
      safeguards = ['Automated software composition analysis (SCA)', 'Continuous dependency patch pipelines'];
    }

    if (!remediationGroups.has(groupKey)) {
      remediationGroups.set(groupKey, {
        title: groupTitle,
        action,
        findingIds: [],
        safeguards,
      });
    }
    remediationGroups.get(groupKey)!.findingIds.push(f.id);
  });

  const items: RemediationItem[] = [];
  let itemIdx = 1;

  for (const [key, group] of remediationGroups.entries()) {
    // Collect all attack paths that touch any of these finding IDs
    const affectedPathIdsSet = new Set<string>();
    group.findingIds.forEach(fid => {
      const paths = findingToPaths.get(fid) || [];
      paths.forEach(pid => affectedPathIdsSet.add(pid));
    });
    const affectedPathIds = Array.from(affectedPathIdsSet);

    // Calculate paths eliminated (if bottleneck finding is fixed)
    const eliminatedPaths = attackPaths.filter(p => 
      group.findingIds.includes(p.remediationBottleneckFindingId || '') ||
      group.findingIds.some(fid => p.participatingFindingIds.includes(fid))
    );

    // Priority calculation
    const hasCriticalPaths = eliminatedPaths.some(p => p.severity === 'Critical');
    const hasHighPaths = eliminatedPaths.some(p => p.severity === 'High');
    const hasCriticalFindings = findings.filter(f => group.findingIds.includes(f.id)).some(f => f.severity === 'Critical');

    let priority: RemediationPriority = 'P2 - Medium';
    if (hasCriticalPaths || (hasCriticalFindings && affectedPathIds.length > 0)) {
      priority = 'P0 - Immediate';
    } else if (hasHighPaths || affectedPathIds.length >= 2 || hasCriticalFindings) {
      priority = 'P1 - High';
    } else if (affectedPathIds.length > 0) {
      priority = 'P2 - Medium';
    } else {
      priority = 'P3 - Low';
    }

    const estimatedReduction = Math.min(
      95,
      Math.max(15, (eliminatedPaths.length * 25) + (group.findingIds.length * 8))
    );

    items.push({
      id: `REM-${projectId.slice(-4)}-${String(itemIdx++).padStart(3, '0')}`,
      projectId,
      title: group.title,
      priority,
      affectedFindingIds: group.findingIds,
      affectedAttackPathIds: affectedPathIds,
      pathsEliminatedCount: eliminatedPaths.length,
      engineeringAction: group.action,
      architecturalSafeguards: group.safeguards,
      validationRequirements: `Verify via targeted security re-test and regression scan that ${group.findingIds.length} finding(s) no longer replicate.`,
      estimatedRiskReductionPercent: estimatedReduction,
      status: 'pending',
    });
  }

  // Sort: P0 first, then P1, then P2, then P3, then by paths eliminated desc
  const prioRank: Record<RemediationPriority, number> = {
    'P0 - Immediate': 4,
    'P1 - High': 3,
    'P2 - Medium': 2,
    'P3 - Low': 1,
  };

  items.sort((a, b) => {
    const pDiff = prioRank[b.priority] - prioRank[a.priority];
    if (pDiff !== 0) return pDiff;
    return b.pathsEliminatedCount - a.pathsEliminatedCount;
  });

  return items;
}

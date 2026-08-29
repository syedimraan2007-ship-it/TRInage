import { AttackPath, AttackPathScoreBreakdown, NormalizedFinding, Severity } from '../../src/types';

export function calculatePathRisk(
  path: Partial<AttackPath>,
  findings: NormalizedFinding[]
): {
  score: number;
  severity: Severity;
  breakdown: AttackPathScoreBreakdown;
} {
  const pathFindings = findings.filter(f => path.participatingFindingIds?.includes(f.id));
  const hasExternalExposure = path.nodes?.some(n => 
    n.type === 'threat_actor' || 
    n.isEntrypoint || 
    n.label.toLowerCase().includes('internet') || 
    n.label.toLowerCase().includes('external') ||
    n.label.toLowerCase().includes('gateway')
  );

  // 1. Exposure Score (0-25)
  let exposureScore = 12;
  if (hasExternalExposure) exposureScore = 25;
  else if (pathFindings.some(f => f.authContext === 'Unauthenticated')) exposureScore = 22;
  else if (pathFindings.some(f => f.authContext === 'Low Privilege')) exposureScore = 16;

  // 2. Exploitability Score (0-25)
  let exploitabilityScore = 10;
  const hasConfirmedEvidence = pathFindings.some(f => 
    f.confidence === 'Confirmed' || 
    (f.evidence?.payload && f.evidence.payload.length > 3) ||
    f.aiTriage?.calibratedConfidence === 'confirmed by evidence'
  );
  const hasCriticalVuln = pathFindings.some(f => f.severity === 'Critical');
  const hasHighVuln = pathFindings.some(f => f.severity === 'High');

  if (hasConfirmedEvidence && hasCriticalVuln) exploitabilityScore = 25;
  else if (hasCriticalVuln) exploitabilityScore = 22;
  else if (hasHighVuln && hasConfirmedEvidence) exploitabilityScore = 20;
  else if (hasHighVuln) exploitabilityScore = 16;
  else exploitabilityScore = 12;

  // 3. Asset & Data Sensitivity Score (0-25)
  let assetCriticalityScore = 12;
  const touchesCrownJewel = path.nodes?.some(n => {
    const l = n.label.toLowerCase();
    return l.includes('payment') || l.includes('vault') || l.includes('database') || l.includes('iam') || l.includes('token') || l.includes('secret') || l.includes('master');
  }) || pathFindings.some(f => f.dataSensitivity === 'Credentials/Secrets' || f.dataSensitivity === 'PII/Financial');

  const touchesInternalDB = path.nodes?.some(n => n.type === 'datastore' || n.label.toLowerCase().includes('db'));

  if (touchesCrownJewel) assetCriticalityScore = 25;
  else if (touchesInternalDB) assetCriticalityScore = 20;
  else if (pathFindings.some(f => f.dataSensitivity === 'Confidential')) assetCriticalityScore = 16;
  else assetCriticalityScore = 12;

  // 4. Chain Impact & Multi-Hop Pivot Score (0-25)
  let chainImpactScore = 10;
  const nodeCount = path.nodes?.length || 0;
  const edgeCount = path.edges?.length || 0;

  if (nodeCount >= 4 && edgeCount >= 3) chainImpactScore = 25;
  else if (nodeCount >= 3) chainImpactScore = 18;
  else chainImpactScore = 12;

  // Bonus / Penalty modifiers
  let bonusPenalties = 0;
  // If unauthenticated full pivot to sensitive target
  if (hasExternalExposure && touchesCrownJewel && hasConfirmedEvidence) {
    bonusPenalties += 5;
  }

  const rawTotal = exposureScore + exploitabilityScore + assetCriticalityScore + chainImpactScore + bonusPenalties;
  const totalScore = Math.min(100, Math.max(10, Math.round(rawTotal)));

  let severity: Severity = 'Low';
  if (totalScore >= 80) severity = 'Critical';
  else if (totalScore >= 60) severity = 'High';
  else if (totalScore >= 40) severity = 'Medium';
  else if (totalScore >= 20) severity = 'Low';
  else severity = 'Info';

  const explanation = `Deterministic Contextual Formula: Exposure (${exposureScore}/25) + Exploitability (${exploitabilityScore}/25) + Asset Criticality (${assetCriticalityScore}/25) + Chain Pivot Impact (${chainImpactScore}/25)${bonusPenalties > 0 ? ` + Unauth Crown-Jewel Modifier (+${bonusPenalties})` : ''} = ${totalScore}/100.`;

  return {
    score: totalScore,
    severity,
    breakdown: {
      exposureScore,
      exploitabilityScore,
      assetCriticalityScore,
      chainImpactScore,
      bonusPenalties,
      totalScore,
      explanation,
    },
  };
}

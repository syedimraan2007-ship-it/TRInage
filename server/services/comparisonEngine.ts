import { AttackPath, NormalizedFinding, Scan, ScanComparison } from '../../src/types';
import { aiGenerateScanComparisonSummary } from './gemini';

export async function compareScans(
  scan1: Scan,
  scan1Findings: NormalizedFinding[],
  scan1Paths: AttackPath[],
  scan2: Scan,
  scan2Findings: NormalizedFinding[],
  scan2Paths: AttackPath[]
): Promise<ScanComparison> {
  // Normalize finding identity key for fuzzy cross-scan matching
  const getKey = (f: NormalizedFinding) => {
    const asset = (f.asset || '').toLowerCase();
    const endpoint = (f.endpoint || '').split('?')[0].toLowerCase();
    const cat = (f.vulnerabilityCategory || f.cwe || f.title).toLowerCase();
    return `${asset}::${endpoint}::${cat}`;
  };

  const scan2KeyMap = new Map<string, NormalizedFinding>();
  scan2Findings.forEach(f => scan2KeyMap.set(getKey(f), f));

  const scan1KeyMap = new Map<string, NormalizedFinding>();
  scan1Findings.forEach(f => scan1KeyMap.set(getKey(f), f));

  const resolvedFindingIds: string[] = [];
  const persistentFindingIds: string[] = [];
  const newFindingIds: string[] = [];

  // Check Scan 1 findings
  scan1Findings.forEach(f1 => {
    const key = getKey(f1);
    if (scan2KeyMap.has(key)) {
      persistentFindingIds.push(f1.id);
    } else {
      resolvedFindingIds.push(f1.id);
    }
  });

  // Check Scan 2 for newly introduced findings
  scan2Findings.forEach(f2 => {
    const key = getKey(f2);
    if (!scan1KeyMap.has(key)) {
      newFindingIds.push(f2.id);
    }
  });

  // Check eliminated attack paths:
  // A path is eliminated if any of its critical contributing findings (or bottleneck finding) are in resolvedFindingIds
  const eliminatedPathIds: string[] = [];
  scan1Paths.forEach(p1 => {
    const isEliminated = p1.participatingFindingIds.some(fid => resolvedFindingIds.includes(fid));
    if (isEliminated) {
      eliminatedPathIds.push(p1.id);
    }
  });

  const newPathIds = scan2Paths.map(p => p.id);

  // Compute risk score deltas
  const scan1TotalRisk = scan1Paths.reduce((acc, p) => acc + p.contextualScore, 0);
  const scan2TotalRisk = scan2Paths.reduce((acc, p) => acc + p.contextualScore, 0);
  const riskScoreDelta = scan2TotalRisk - scan1TotalRisk;
  const scoreReductionPct = scan1TotalRisk > 0
    ? Math.max(0, Math.round(((scan1TotalRisk - scan2TotalRisk) / scan1TotalRisk) * 100))
    : 0;

  const resolvedTitles = scan1Findings
    .filter(f => resolvedFindingIds.includes(f.id))
    .map(f => f.title);

  const eliminatedPathTitles = scan1Paths
    .filter(p => eliminatedPathIds.includes(p.id))
    .map(p => p.title);

  const aiSummary = await aiGenerateScanComparisonSummary({
    scan1Name: scan1.filename,
    scan2Name: scan2.filename,
    resolvedCount: resolvedFindingIds.length,
    persistentCount: persistentFindingIds.length,
    newCount: newFindingIds.length,
    eliminatedPathsCount: eliminatedPathIds.length,
    newPathsCount: newPathIds.length,
    riskScoreDelta,
    resolvedTitles,
    eliminatedPathTitles,
  });

  return {
    id: `CMP-${scan1.id.slice(-4)}-${scan2.id.slice(-4)}`,
    projectId: scan1.projectId,
    scan1Id: scan1.id,
    scan2Id: scan2.id,
    scan1Name: scan1.filename,
    scan2Name: scan2.filename,
    createdAt: new Date().toISOString(),
    resolvedFindingIds,
    persistentFindingIds,
    newFindingIds,
    eliminatedPathIds,
    newPathIds,
    riskScoreDelta,
    riskDelta: {
      beforeScore: scan1TotalRisk,
      afterScore: scan2TotalRisk,
      scoreReductionPct,
    },
    aiSummary,
  };
}

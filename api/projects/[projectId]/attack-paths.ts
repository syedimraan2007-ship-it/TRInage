import { createSupabaseClient } from '../../../lib/supabase';
import { getAttackPaths } from '../../../lib/vercel-store';

function normalizePath(row: any) {
  return {
    id: row.id,
    projectId: row.project_id ?? row.projectId,
    scanId: row.scan_id ?? row.scanId,
    title: row.title,
    summary: row.summary,
    nodes: row.nodes ?? [],
    edges: row.edges ?? [],
    participatingFindingIds: row.participating_finding_ids ?? row.participatingFindingIds ?? [],
    participatingAssets: row.participating_assets ?? row.participatingAssets ?? [],
    prerequisites: row.prerequisites ?? [],
    impactAssessment: row.impact_assessment ?? row.impactAssessment,
    contextualScore: row.contextual_score ?? row.contextualScore ?? 0,
    severity: row.severity,
    confidence: row.confidence,
    scoreBreakdown: row.score_breakdown ?? row.scoreBreakdown ?? {
      exposureScore: 0,
      exploitabilityScore: 0,
      assetCriticalityScore: 0,
      chainImpactScore: 0,
      bonusPenalties: 0,
      totalScore: 0,
      explanation: '',
    },
    recommendedFixSequence: row.recommended_fix_sequence ?? row.recommendedFixSequence ?? [],
    remediationBottleneckFindingId: row.remediation_bottleneck_finding_id ?? row.remediationBottleneckFindingId,
    status: row.status ?? 'active',
  };
}

export default async function handler(req: any, res: any) {
  const rawProjectId = Array.isArray(req.query.projectId) ? req.query.projectId[0] : req.query.projectId;
  const projectId = rawProjectId || '';
  const supabase = createSupabaseClient(true) || createSupabaseClient();

  if (req.method === 'GET') {
    const { scanId } = req.query;

    if (supabase) {
      try {
        let query = supabase.from('attack_paths').select('*').eq('project_id', projectId);
        if (scanId) query = query.eq('scan_id', String(scanId));
        const { data, error } = await query.order('contextual_score', { ascending: false });
        if (!error && data) {
          return res.status(200).json(data.map(normalizePath));
        }
      } catch {}
    }

    const paths = getAttackPaths(projectId, scanId ? String(scanId) : undefined);
    return res.status(200).json(paths);
  }

  res.setHeader('Allow', 'GET');
  return res.status(405).json({ error: 'Method not allowed' });
}

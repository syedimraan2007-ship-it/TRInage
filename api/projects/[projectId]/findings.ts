import { createSupabaseClient, getSupabaseSetupError } from '../../../lib/supabase';

function normalizeFinding(row: any) {
  return {
    id: row.id,
    scanId: row.scan_id ?? row.scanId,
    projectId: row.project_id ?? row.projectId,
    title: row.title,
    vulnerabilityCategory: row.vulnerability_category ?? row.vulnerabilityCategory,
    cwe: row.cwe ?? undefined,
    cve: row.cve ?? undefined,
    severity: row.severity,
    confidence: row.confidence,
    asset: row.asset,
    hostname: row.hostname ?? undefined,
    ip: row.ip ?? undefined,
    port: row.port ?? undefined,
    protocol: row.protocol ?? undefined,
    service: row.service ?? undefined,
    technology: row.technology ?? [],
    endpoint: row.endpoint ?? undefined,
    httpMethod: row.http_method ?? row.httpMethod ?? undefined,
    parameter: row.parameter ?? undefined,
    affectedComponent: row.affected_component ?? row.affectedComponent ?? undefined,
    evidence: row.evidence ?? {},
    description: row.description ?? '',
    authContext: row.auth_context ?? row.authContext ?? 'Unauthenticated',
    privilegeContext: row.privilege_context ?? row.privilegeContext ?? undefined,
    dataSensitivity: row.data_sensitivity ?? row.dataSensitivity ?? 'Internal',
    status: row.status ?? 'open',
    dedupGroupId: row.dedup_group_id ?? row.dedupGroupId,
    sourceCount: row.source_count ?? row.sourceCount ?? 1,
    provenance: row.provenance ?? [],
    aiTriage: row.ai_triage ?? row.aiTriage ?? undefined,
    createdAt: row.created_at ?? row.createdAt,
  };
}

export default async function handler(req: any, res: any) {
  const rawProjectId = Array.isArray(req.query.projectId) ? req.query.projectId[0] : req.query.projectId;
  const projectId = rawProjectId || '';
  const supabase = createSupabaseClient(true) || createSupabaseClient();

  if (!supabase) {
    return res.status(503).json({ error: getSupabaseSetupError() });
  }

  if (req.method === 'GET') {
    const { scanId, severity, asset, status, search } = req.query;

    let query = supabase
      .from('findings')
      .select('*')
      .eq('project_id', projectId);

    if (scanId) {
      query = query.eq('scan_id', String(scanId));
    }
    if (severity) {
      query = query.eq('severity', String(severity));
    }
    if (status) {
      query = query.eq('status', String(status));
    }

    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) {
      return res.status(500).json({ error: error.message });
    }

    let rows = (data || []).map(normalizeFinding);
    if (asset) {
      const target = String(asset).toLowerCase();
      rows = rows.filter(f => String(f.asset || '').toLowerCase().includes(target));
    }
    if (search) {
      const q = String(search).toLowerCase();
      rows = rows.filter(f =>
        (f.title || '').toLowerCase().includes(q) ||
        (f.endpoint || '').toLowerCase().includes(q) ||
        (f.cwe || '').toLowerCase().includes(q) ||
        (f.cve || '').toLowerCase().includes(q) ||
        (f.vulnerabilityCategory || '').toLowerCase().includes(q)
      );
    }

    return res.status(200).json(rows);
  }

  if (req.method === 'PATCH') {
    const findingId = Array.isArray(req.query.id) ? req.query.id[0] : req.query.id;
    const { status } = req.body || {};

    if (!findingId) {
      return res.status(400).json({ error: 'Finding id is required.' });
    }

    const { data, error } = await supabase
      .from('findings')
      .update({ status, updated_at: new Date().toISOString() })
      .eq('id', findingId)
      .select('*')
      .single();

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    return res.status(200).json(normalizeFinding(data));
  }

  res.setHeader('Allow', 'GET, PATCH');
  return res.status(405).json({ error: 'Method not allowed' });
}

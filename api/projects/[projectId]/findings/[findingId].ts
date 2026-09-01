import { createSupabaseClient } from '../../../../lib/supabase';
import { getFinding, updateFinding } from '../../../../lib/vercel-store';

export default async function handler(req: any, res: any) {
  if (req.method !== 'PATCH') {
    res.setHeader('Allow', 'PATCH');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const rawFindingId = Array.isArray(req.query.findingId) ? req.query.findingId[0] : req.query.findingId;
  const findingId = rawFindingId || '';
  const { status } = req.body || {};

  if (!findingId) {
    return res.status(400).json({ error: 'Finding id is required.' });
  }

  const supabase = createSupabaseClient(true) || createSupabaseClient();
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('findings')
        .update({ status, updated_at: new Date().toISOString() })
        .eq('id', findingId)
        .select('*')
        .single();
      if (!error && data) {
        return res.status(200).json(data);
      }
    } catch {}
  }

  updateFinding(findingId, { status });
  const updated = getFinding(findingId);
  return res.status(200).json(updated || { id: findingId, status });
}

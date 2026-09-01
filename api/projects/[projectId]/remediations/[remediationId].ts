import { getRemediations, updateRemediation } from '../../../../lib/vercel-store';

export default async function handler(req: any, res: any) {
  if (req.method !== 'PATCH') {
    res.setHeader('Allow', 'PATCH');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const rawProjectId = Array.isArray(req.query.projectId) ? req.query.projectId[0] : req.query.projectId;
  const rawRemediationId = Array.isArray(req.query.remediationId) ? req.query.remediationId[0] : req.query.remediationId;
  const projectId = rawProjectId || '';
  const remediationId = rawRemediationId || '';
  const { status, assignedTo } = req.body || {};

  if (!remediationId) {
    return res.status(400).json({ error: 'Remediation id is required.' });
  }

  updateRemediation(remediationId, { status, assignedTo });
  const items = getRemediations(projectId);
  const found = items.find((i: any) => i.id === remediationId);
  return res.status(200).json(found || { id: remediationId, status });
}

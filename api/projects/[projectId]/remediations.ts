import { getProject, getRemediations, setRemediations, updateRemediation } from '../../../lib/vercel-store';

export default async function handler(req: any, res: any) {
  const rawProjectId = Array.isArray(req.query.projectId) ? req.query.projectId[0] : req.query.projectId;
  const projectId = rawProjectId || '';

  if (!getProject(projectId)) {
    return res.status(404).json({ error: 'Project not found.' });
  }

  if (req.method === 'GET') {
    return res.status(200).json(getRemediations(projectId));
  }

  if (req.method === 'PATCH') {
    const remediationId = Array.isArray(req.query.id) ? req.query.id[0] : req.query.id;
    const { status, assignedTo } = req.body || {};

    if (!remediationId) {
      return res.status(400).json({ error: 'Remediation id is required.' });
    }

    updateRemediation(remediationId, { status, assignedTo });
    const items = getRemediations(projectId);
    return res.status(200).json(items.find((item: any) => item.id === remediationId));
  }

  res.setHeader('Allow', 'GET, PATCH');
  return res.status(405).json({ error: 'Method not allowed' });
}

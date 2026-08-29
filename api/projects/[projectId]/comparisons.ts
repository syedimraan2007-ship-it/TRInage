import { getProject, getComparisons } from '../../../lib/vercel-store';

export default async function handler(req: any, res: any) {
  const rawProjectId = Array.isArray(req.query.projectId) ? req.query.projectId[0] : req.query.projectId;
  const projectId = rawProjectId || '';

  if (!getProject(projectId)) {
    return res.status(404).json({ error: 'Project not found.' });
  }

  if (req.method === 'GET') {
    return res.status(200).json(getComparisons(projectId));
  }

  res.setHeader('Allow', 'GET');
  return res.status(405).json({ error: 'Method not allowed' });
}

import { getProject, deleteProject } from '../../lib/vercel-store';

export default async function handler(req: any, res: any) {
  const rawProjectId = Array.isArray(req.query.projectId) ? req.query.projectId[0] : req.query.projectId;
  const projectId = rawProjectId || '';

  if (req.method === 'GET') {
    const project = getProject(projectId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found.' });
    }
    return res.status(200).json(project);
  }

  if (req.method === 'DELETE') {
    const success = deleteProject(projectId);
    if (!success) {
      return res.status(404).json({ error: 'Project not found.' });
    }
    return res.status(200).json({ success: true, message: 'Project deleted successfully.' });
  }

  res.setHeader('Allow', 'GET, DELETE');
  return res.status(405).json({ error: 'Method not allowed' });
}

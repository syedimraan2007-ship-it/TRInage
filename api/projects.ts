import { createProject, getProjects } from '../lib/vercel-store';

export default async function handler(req: any, res: any) {
  if (req.method === 'GET') {
    return res.status(200).json(getProjects());
  }

  if (req.method === 'POST') {
    const { name, targetScope, authorizedBy, description } = req.body || {};

    if (!name || !targetScope) {
      return res.status(400).json({ error: 'Project name and target scope are required.' });
    }

    const project = createProject({ name, targetScope, authorizedBy, description: description || '' });
    return res.status(201).json(project);
  }

  res.setHeader('Allow', 'GET, POST');
  return res.status(405).json({ error: 'Method not allowed' });
}

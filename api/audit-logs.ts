import { getAuditLogs } from '../lib/vercel-store';

export default async function handler(req: any, res: any) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const projectId = req.query.projectId ? String(req.query.projectId) : undefined;
  return res.status(200).json(getAuditLogs(projectId));
}

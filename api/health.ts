export default async function handler(req: any, res: any) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  return res.status(200).json({
    status: 'ok',
    service: 'ai-vulnerability-triage-and-attack-path-prioritizer',
    mode: 'vercel-serverless',
    timestamp: new Date().toISOString(),
  });
}

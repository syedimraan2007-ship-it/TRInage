import { resetCleanDemo } from '../../lib/vercel-store';

export default async function handler(req: any, res: any) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const project = resetCleanDemo();
  return res.status(200).json({ success: true, project });
}

import { createApiApp } from '../server/app';

const app = createApiApp();

export default function handler(req: any, res: any) {
  // Normalize URL from Vercel rewrites or headers
  try {
    if (req.query && req.query.__path) {
      const subpath = Array.isArray(req.query.__path) ? req.query.__path.join('/') : String(req.query.__path);
      const urlObj = new URL(req.url, 'http://localhost');
      urlObj.searchParams.delete('__path');
      const qs = urlObj.searchParams.toString();
      req.url = '/' + subpath + (qs ? `?${qs}` : '');
    } else if (req.headers['x-matched-path']) {
      const matched = String(req.headers['x-matched-path']);
      req.url = matched.startsWith('/api') ? matched : `/api${matched}`;
    }
  } catch {}

  return app(req, res);
}

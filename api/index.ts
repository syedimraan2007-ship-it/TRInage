import { createApiApp } from '../server/app';

const app = createApiApp();

export default function handler(req: any, res: any) {
  return new Promise<void>((resolve, reject) => {
    res.on('finish', () => resolve());
    res.on('close', () => resolve());
    res.on('error', (err: any) => reject(err));
    app(req, res);
  });
}

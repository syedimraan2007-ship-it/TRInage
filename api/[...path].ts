import { createApiApp } from '../server/app';

const app = createApiApp();

export default function handler(req: any, res: any) {
  return app(req, res);
}

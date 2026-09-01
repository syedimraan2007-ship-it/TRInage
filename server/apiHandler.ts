import { handleApiRequest } from './router';

export default async function handler(req: any, res: any) {
  return handleApiRequest(req, res);
}

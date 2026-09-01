import { handleApiRequest } from '../server/router';

export default async function handler(req: any, res: any) {
  return handleApiRequest(req, res);
}

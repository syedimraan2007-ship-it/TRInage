import { getRemediations, getFindings, updateRemediation } from '../../../../../lib/vercel-store';
import { aiGenerateRemediationGuidance } from '../../../../../server/services/gemini';

export default async function handler(req: any, res: any) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const rawProjectId = Array.isArray(req.query.projectId) ? req.query.projectId[0] : req.query.projectId;
  const rawRemediationId = Array.isArray(req.query.remediationId) ? req.query.remediationId[0] : req.query.remediationId;
  const projectId = rawProjectId || '';
  const remediationId = rawRemediationId || '';

  const remediations = getRemediations(projectId);
  const remediation = remediations.find((r: any) => r.id === remediationId);
  if (!remediation) {
    return res.status(404).json({ error: 'Remediation task not found.' });
  }

  if (remediation.aiGuidance) {
    return res.status(200).json(remediation.aiGuidance);
  }

  const findings = getFindings(projectId).filter((f: any) => remediation.affectedFindingIds.includes(f.id));

  try {
    const guidance = await aiGenerateRemediationGuidance(remediation, findings);
    updateRemediation(remediationId, { aiGuidance: guidance });
    return res.status(200).json(guidance);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
}

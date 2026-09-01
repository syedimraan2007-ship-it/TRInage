export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export type Confidence = 'Confirmed' | 'High' | 'Medium' | 'Low' | 'Unknown';
export type FindingStatus = 'open' | 'in_progress' | 'verified_fixed' | 'false_positive';
export type RemediationPriority = 'P0 - Immediate' | 'P1 - High' | 'P2 - Medium' | 'P3 - Low';

export interface Project {
  id: string;
  name: string;
  targetScope: string;
  authorizedBy: string;
  createdAt: string;
  updatedAt: string;
  description: string;
  scanCount?: number;
  openFindingCount?: number;
  attackPathCount?: number;
}

export interface Scan {
  id: string;
  projectId: string;
  filename: string;
  scannerType: 'zap' | 'nuclei' | 'nmap' | 'semgrep' | 'trivy' | 'generic_json' | 'generic_csv' | 'custom';
  uploadedAt: string;
  totalRawFindings: number;
  deduplicatedCount: number;
  status: 'uploaded' | 'parsing' | 'normalized' | 'analyzing' | 'correlating' | 'building_paths' | 'completed' | 'failed';
  statusMessage?: string;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  metadata?: Record<string, unknown>;
}

export interface RawFindingSource {
  scanner: string;
  scannerFindingId?: string;
  rawJson?: string;
  timestamp: string;
  scanId: string;
}

export interface AiTriageResult {
  relevance: 'High' | 'Medium' | 'Low' | 'Informational' | 'False Positive Likely';
  calibratedConfidence: 'confirmed by evidence' | 'strongly indicated' | 'potentially exploitable' | 'insufficient evidence' | 'requires manual verification';
  contextualSeverity: Severity;
  businessImpact: string;
  exploitabilityAssessment: string;
  evidenceQuality: 'High' | 'Moderate' | 'Weak' | 'Synthetic/Heuristic';
  manualVerificationRecommended: boolean;
  reasoning: string;
  keyRiskFactors: string[];
}

export interface NormalizedFinding {
  id: string;
  scanId: string;
  projectId: string;
  title: string;
  vulnerabilityCategory: string;
  cwe?: string;
  cve?: string;
  severity: Severity;
  confidence: Confidence;
  asset: string;
  hostname?: string;
  ip?: string;
  port?: number;
  protocol?: string;
  service?: string;
  technology?: string[];
  endpoint?: string;
  httpMethod?: string;
  parameter?: string;
  affectedComponent?: string;
  evidence?: {
    request?: string;
    response?: string;
    payload?: string;
    matchedPattern?: string;
    rawOutput?: string;
  };
  description: string;
  authContext?: 'Unauthenticated' | 'Low Privilege' | 'High Privilege' | 'Internal Service';
  privilegeContext?: string;
  dataSensitivity?: 'Public' | 'Internal' | 'Confidential' | 'PII/Financial' | 'Credentials/Secrets';
  status: FindingStatus;
  dedupGroupId: string;
  sourceCount: number;
  provenance: RawFindingSource[];
  aiTriage?: AiTriageResult;
  createdAt: string;
}

export interface FindingRelationship {
  id: string;
  projectId: string;
  sourceFindingId: string;
  targetFindingId: string;
  relationshipType: 'enables' | 'leaks_credential_for' | 'exposes_service_to' | 'pivots_to' | 'bypasses_defense_of' | 'prerequisites';
  confidence: 'Confirmed' | 'Strongly Indicated' | 'Hypothesized';
  reasoning: string;
  isAiDerived: boolean;
}

export interface AttackPathNode {
  id: string;
  type: 'threat_actor' | 'asset' | 'service' | 'vulnerability' | 'identity' | 'datastore';
  label: string;
  subLabel?: string;
  assetRef?: string;
  findingRef?: string;
  severity?: Severity;
  isEntrypoint?: boolean;
  isTarget?: boolean;
}

export interface AttackPathEdge {
  id: string;
  fromNodeId: string;
  toNodeId: string;
  relation: string;
  label: string;
  riskWeight: number;
}

export interface AttackPathScoreBreakdown {
  exposureScore: number;
  exploitabilityScore: number;
  assetCriticalityScore: number;
  chainImpactScore: number;
  bonusPenalties: number;
  totalScore: number;
  explanation: string;
}

export interface AttackPath {
  id: string;
  projectId: string;
  scanId: string;
  title: string;
  summary: string;
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  participatingFindingIds: string[];
  participatingAssets: string[];
  prerequisites: string[];
  impactAssessment: string;
  contextualScore: number; // 0 to 100
  severity: Severity;
  confidence: 'Confirmed' | 'Strongly Indicated' | 'Hypothesized';
  scoreBreakdown: AttackPathScoreBreakdown;
  recommendedFixSequence: string[];
  remediationBottleneckFindingId?: string;
  status: 'active' | 'mitigated' | 'eliminated';
}

export interface RemediationItem {
  id: string;
  projectId: string;
  title: string;
  priority: RemediationPriority;
  affectedAsset?: string;
  affectedFindingIds: string[];
  affectedAttackPathIds: string[];
  pathsEliminatedCount: number;
  engineeringAction: string;
  architecturalSafeguards: string[];
  validationRequirements: string;
  estimatedRiskReductionPercent: number;
  status: 'pending' | 'in_progress' | 'verified_fixed';
  assignedTo?: string;
  aiGuidance?: {
    rootCauseExplanation: string;
    impactRationale: string;
    remediationBlueprint: string;
    verificationSteps: string[];
    residualRiskNotes: string;
  };
}

export interface ScanComparison {
  id: string;
  projectId: string;
  scan1Id: string;
  scan2Id: string;
  scan1Name: string;
  scan2Name: string;
  createdAt: string;
  resolvedFindingIds: string[];
  persistentFindingIds: string[];
  newFindingIds: string[];
  eliminatedPathIds: string[];
  newPathIds: string[];
  riskScoreDelta: number; // e.g. -42 points
  aiSummary: string;
}

export interface DashboardMetrics {
  totalFindings: number;
  uniqueFindings: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  infoFindings: number;
  activeAttackPaths: number;
  criticalAttackPaths: number;
  affectedAssets: string[];
  unresolvedRemediations: number;
  resolvedRemediations: number;
  averageContextualRisk: number;
  postureRating: 'CRITICAL RISK' | 'ELEVATED RISK' | 'MODERATE RISK' | 'SECURE POSTURE';
}

export interface AssessmentReport {
  project: Project;
  scan: Scan;
  metrics: DashboardMetrics;
  topAttackPaths: AttackPath[];
  prioritizedRemediations: RemediationItem[];
  highRiskAssets: { asset: string; findingCount: number; maxSeverity: Severity; criticalPathsCount: number }[];
  methodology: string;
  aiLimitations: string;
  generatedAt: string;
}

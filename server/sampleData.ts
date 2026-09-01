import { Project, NormalizedFinding, AttackPath, RemediationItem } from '../src/types';

export const SAMPLE_PROJECT: Project = {
  id: 'PRJ-FINTECH-CORE',
  name: 'Fintech Payments & Auth Subsystem',
  targetScope: '*.payments.enterprise.internal',
  authorizedBy: 'SecOps Threat Modeling Team (Lead Architect)',
  description: 'Production-grade defensive threat modeling for payment gateway, microservices API, Redis session caching, and backend customer ledger.',
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

export const SAMPLE_FINDINGS: NormalizedFinding[] = [
  {
    id: 'FND-SSRF-01',
    scanId: 'SCN-SAMPLE-01',
    projectId: 'PRJ-FINTECH-CORE',
    title: 'Server-Side Request Forgery (SSRF) in Webhook Dispatcher',
    vulnerabilityCategory: 'Server-Side Request Forgery',
    cwe: 'CWE-918',
    cve: 'CVE-2024-38856',
    severity: 'Critical',
    confidence: 'Confirmed',
    asset: 'api.payments.enterprise.internal',
    hostname: 'api.payments.enterprise.internal',
    endpoint: '/api/v2/webhooks/subscribe',
    httpMethod: 'POST',
    parameter: 'callback_url',
    description: 'The webhook registration endpoint allows unauthenticated callers to specify arbitrary destination URLs, permitting internal network pivoting to cloud metadata and private microservices.',
    affectedComponent: 'WebhookService.ts',
    evidence: {
      request: 'POST /api/v2/webhooks/subscribe HTTP/1.1\nHost: api.payments.enterprise.internal\nContent-Type: application/json\n\n{"callback_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}',
      response: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"status": "active", "reflected_response": "role-arn: payments-core-worker"}',
      payload: 'http://169.254.169.254/latest/meta-data/',
    },
    authContext: 'Unauthenticated',
    dataSensitivity: 'Confidential',
    status: 'open',
    dedupGroupId: 'DEDUP-SSRF-01',
    sourceCount: 2,
    createdAt: new Date().toISOString(),
    provenance: [
      { scanner: 'OWASP ZAP 2.15', scannerFindingId: 'ZAP-918-01', timestamp: new Date().toISOString(), scanId: 'SCN-SAMPLE-01' },
      { scanner: 'Nuclei v3.2', scannerFindingId: 'nuclei-ssrf-meta', timestamp: new Date().toISOString(), scanId: 'SCN-SAMPLE-01' },
    ],
    aiTriage: {
      relevance: 'High',
      calibratedConfidence: 'confirmed by evidence',
      contextualSeverity: 'Critical',
      businessImpact: 'Unauthenticated attackers can query cloud metadata service (IMDSv1) and pivot to internal payment databases.',
      exploitabilityAssessment: 'Directly exploitable without prior authentication via public webhook subscription endpoint.',
      evidenceQuality: 'High',
      manualVerificationRecommended: false,
      reasoning: 'Scanner evidence confirmed IAM credential reflection in response body.',
      keyRiskFactors: ['Unauthenticated Ingress', 'Cloud Metadata Access', 'Lateral Pivot Gateway'],
    },
  },
  {
    id: 'FND-REDIS-02',
    scanId: 'SCN-SAMPLE-01',
    projectId: 'PRJ-FINTECH-CORE',
    title: 'Unauthenticated Redis Cache Exposed on Internal Subnet',
    vulnerabilityCategory: 'Broken Access Control',
    cwe: 'CWE-306',
    cve: 'CVE-2023-36824',
    severity: 'High',
    confidence: 'Confirmed',
    asset: 'redis.payments.internal',
    hostname: 'redis.payments.internal',
    endpoint: ':6379',
    description: 'Internal Redis cluster instance lacks authentication requirement (requirepass disabled), allowing arbitrary read and write of session tokens and payment nonce caches.',
    affectedComponent: 'redis-cache:6379',
    evidence: {
      rawOutput: 'INFO Server\nredis_version: 7.0.11\nrole: master\nkeyspace: db0:keys=14205,expires=8920',
      payload: 'redis-cli -h redis.payments.internal INFO',
    },
    authContext: 'Internal Service',
    dataSensitivity: 'Credentials/Secrets',
    status: 'open',
    dedupGroupId: 'DEDUP-REDIS-02',
    sourceCount: 1,
    createdAt: new Date().toISOString(),
    provenance: [
      { scanner: 'Nuclei v3.2', scannerFindingId: 'nuclei-redis-unauth', timestamp: new Date().toISOString(), scanId: 'SCN-SAMPLE-01' },
    ],
    aiTriage: {
      relevance: 'High',
      calibratedConfidence: 'confirmed by evidence',
      contextualSeverity: 'High',
      businessImpact: 'Complete compromise of active session keys and merchant authentication tokens stored in volatile cache.',
      exploitabilityAssessment: 'Exploitable once perimeter access or internal network pivot (e.g. via SSRF) is established.',
      evidenceQuality: 'High',
      manualVerificationRecommended: false,
      reasoning: 'Direct response to INFO command returned full cluster status without AUTH challenge.',
      keyRiskFactors: ['Session Hijacking', 'Internal Pivot Target', 'Zero-Auth Cache'],
    },
  },
  {
    id: 'FND-SQLI-03',
    scanId: 'SCN-SAMPLE-01',
    projectId: 'PRJ-FINTECH-CORE',
    title: 'SQL Injection in Settlement Reconciliation Query',
    vulnerabilityCategory: 'SQL Injection',
    cwe: 'CWE-89',
    cve: 'CVE-2024-21626',
    severity: 'Critical',
    confidence: 'Confirmed',
    asset: 'ledger.payments.internal',
    hostname: 'ledger.payments.internal',
    endpoint: '/api/v1/ledger/reconcile',
    httpMethod: 'GET',
    parameter: 'batch_id',
    description: 'The settlement batch reconciliation endpoint constructs raw SQL queries via string concatenation, allowing extraction of full cardholder ledger tables.',
    affectedComponent: 'LedgerRepository.ts:88',
    evidence: {
      request: "GET /api/v1/ledger/reconcile?batch_id=1' UNION SELECT 1,version(),current_user,schema()-- HTTP/1.1",
      response: 'HTTP/1.1 200 OK\n{"batch_id": 1, "ledger_owner": "postgres@payments-db-prod", "version": "PostgreSQL 16.2"}',
      payload: "' UNION SELECT 1,version(),current_user,schema()--",
    },
    authContext: 'Internal Service',
    dataSensitivity: 'PII/Financial',
    status: 'open',
    dedupGroupId: 'DEDUP-SQLI-03',
    sourceCount: 2,
    createdAt: new Date().toISOString(),
    provenance: [
      { scanner: 'Semgrep SAST 1.68', scannerFindingId: 'semgrep-sqli-ledger', timestamp: new Date().toISOString(), scanId: 'SCN-SAMPLE-01' },
      { scanner: 'OWASP ZAP 2.15', scannerFindingId: 'ZAP-89-02', timestamp: new Date().toISOString(), scanId: 'SCN-SAMPLE-01' },
    ],
    aiTriage: {
      relevance: 'High',
      calibratedConfidence: 'confirmed by evidence',
      contextualSeverity: 'Critical',
      businessImpact: 'Direct exfiltration and modification of production payment ledgers and customer transaction records.',
      exploitabilityAssessment: 'Confirmed SQL injection with schema extraction payload execution.',
      evidenceQuality: 'High',
      manualVerificationRecommended: false,
      reasoning: 'Database metadata was reflected in response object confirming successful injection.',
      keyRiskFactors: ['Crown Jewel Data Loss', 'Financial Ledger Tampering', 'High Exploitability'],
    },
  },
  {
    id: 'FND-CORS-04',
    scanId: 'SCN-SAMPLE-01',
    projectId: 'PRJ-FINTECH-CORE',
    title: 'Overly Permissive Cross-Origin Resource Sharing (CORS)',
    vulnerabilityCategory: 'Security Misconfiguration',
    cwe: 'CWE-942',
    severity: 'Medium',
    confidence: 'Confirmed',
    asset: 'api.payments.enterprise.internal',
    hostname: 'api.payments.enterprise.internal',
    endpoint: '/api/v1/user/profile',
    httpMethod: 'OPTIONS',
    description: 'API returns Access-Control-Allow-Origin: * alongside Access-Control-Allow-Credentials: true, enabling cross-site data theft from logged-in browser sessions.',
    affectedComponent: 'CorsMiddleware.ts',
    evidence: {
      request: 'OPTIONS /api/v1/user/profile HTTP/1.1\nOrigin: https://evil-attacker.com',
      response: 'Access-Control-Allow-Origin: https://evil-attacker.com\nAccess-Control-Allow-Credentials: true',
      payload: 'Origin: https://evil-attacker.com',
    },
    authContext: 'Low Privilege',
    dataSensitivity: 'Confidential',
    status: 'open',
    dedupGroupId: 'DEDUP-CORS-04',
    sourceCount: 1,
    createdAt: new Date().toISOString(),
    provenance: [
      { scanner: 'OWASP ZAP 2.15', scannerFindingId: 'ZAP-942-01', timestamp: new Date().toISOString(), scanId: 'SCN-SAMPLE-01' },
    ],
    aiTriage: {
      relevance: 'Medium',
      calibratedConfidence: 'confirmed by evidence',
      contextualSeverity: 'Medium',
      businessImpact: 'Authenticated user session data can be scraped by malicious third-party websites visited by employees.',
      exploitabilityAssessment: 'Requires user interaction (phishing link or malicious origin visit).',
      evidenceQuality: 'High',
      manualVerificationRecommended: false,
      reasoning: 'Wildcard/reflected origin with credentials verified by header response inspection.',
      keyRiskFactors: ['Cross-Site Data Theft', 'Browser Origin Bypass'],
    },
  },
  {
    id: 'FND-JWT-05',
    scanId: 'SCN-SAMPLE-01',
    projectId: 'PRJ-FINTECH-CORE',
    title: 'Hardcoded Weak JWT Signing Secret in Service Configuration',
    vulnerabilityCategory: 'Cryptographic Issues',
    cwe: 'CWE-798',
    cve: 'CVE-2023-45853',
    severity: 'High',
    confidence: 'Confirmed',
    asset: 'auth.payments.enterprise.internal',
    hostname: 'auth.payments.enterprise.internal',
    endpoint: '/auth/verify',
    description: 'The internal microservice authentication module uses a static hardcoded HMAC key ("payments_secret_key_2024!"), permitting arbitrary token forgery.',
    affectedComponent: 'src/config/jwt.ts:14',
    evidence: {
      rawOutput: "const JWT_SECRET = process.env.JWT_SECRET || 'payments_secret_key_2024!';",
      payload: 'Static string literal detected in codebase',
    },
    authContext: 'Internal Service',
    dataSensitivity: 'Credentials/Secrets',
    status: 'open',
    dedupGroupId: 'DEDUP-JWT-05',
    sourceCount: 1,
    createdAt: new Date().toISOString(),
    provenance: [
      { scanner: 'Semgrep SAST 1.68', scannerFindingId: 'semgrep-jwt-hardcoded', timestamp: new Date().toISOString(), scanId: 'SCN-SAMPLE-01' },
    ],
    aiTriage: {
      relevance: 'High',
      calibratedConfidence: 'confirmed by evidence',
      contextualSeverity: 'High',
      businessImpact: 'Attacker who knows the hardcoded secret can mint administrative JWTs with elevated authorization claims.',
      exploitabilityAssessment: 'Trivial token generation once the static secret is known or decompiled.',
      evidenceQuality: 'High',
      manualVerificationRecommended: false,
      reasoning: 'Hardcoded fallback value discovered in production build code path.',
      keyRiskFactors: ['Privilege Escalation', 'Universal Token Forgery'],
    },
  },
];

export const SAMPLE_ATTACK_PATHS: AttackPath[] = [
  {
    id: 'PATH-01-CRIT',
    scanId: 'SCN-SAMPLE-01',
    projectId: 'PRJ-FINTECH-CORE',
    title: 'Public SSRF → Internal Redis Compromise → Ledger SQLi Extraction',
    summary: 'An unauthenticated attacker exploits SSRF on the public webhook API to reach the unauthenticated Redis cache, acquires internal service credentials, and pivots to the settlement ledger database via SQL injection.',
    severity: 'Critical',
    confidence: 'Strongly Indicated',
    contextualScore: 94,
    scoreBreakdown: {
      exposureScore: 24,
      exploitabilityScore: 24,
      assetCriticalityScore: 25,
      chainImpactScore: 21,
      bonusPenalties: 0,
      totalScore: 94,
      explanation: 'Formula: Exposure (24/25) + Exploitability (24/25) + Asset Criticality (25/25) + Chain Multiplier (21/25) = 94/100.',
    },
    nodes: [
      { id: 'node-0', label: 'Internet Threat Actor', type: 'threat_actor', isEntrypoint: true },
      { id: 'node-1', label: 'Public Webhook API', subLabel: 'api.payments.enterprise.internal', type: 'service', isEntrypoint: true },
      { id: 'node-2', label: 'SSRF in Webhook Dispatcher', subLabel: 'CWE-918 / CVE-2024-38856', type: 'vulnerability', findingRef: 'FND-SSRF-01', severity: 'Critical' },
      { id: 'node-3', label: 'Unauthenticated Redis Cache', subLabel: 'redis.payments.internal:6379', type: 'asset', findingRef: 'FND-REDIS-02', severity: 'High' },
      { id: 'node-4', label: 'SQL Injection in Ledger', subLabel: 'CWE-89 (LedgerRepository)', type: 'vulnerability', findingRef: 'FND-SQLI-03', severity: 'Critical' },
      { id: 'node-5', label: 'Customer Transaction Ledger DB', subLabel: 'PostgreSQL Production Data', type: 'datastore', isTarget: true },
    ],
    edges: [
      { id: 'e1', fromNodeId: 'node-0', toNodeId: 'node-1', relation: 'accesses', label: 'HTTP POST /subscribe', riskWeight: 20 },
      { id: 'e2', fromNodeId: 'node-1', toNodeId: 'node-2', relation: 'triggers', label: 'Inject SSRF Payload', riskWeight: 30 },
      { id: 'e3', fromNodeId: 'node-2', toNodeId: 'node-3', relation: 'pivots_to', label: 'Pivot to Internal Redis (Port 6379)', riskWeight: 25 },
      { id: 'e4', fromNodeId: 'node-3', toNodeId: 'node-4', relation: 'leaks_credential_for', label: 'Steal Ledger Auth Token', riskWeight: 20 },
      { id: 'e5', fromNodeId: 'node-4', toNodeId: 'node-5', relation: 'compromises', label: 'Dump Cardholder Table', riskWeight: 35 },
    ],
    participatingFindingIds: ['FND-SSRF-01', 'FND-REDIS-02', 'FND-SQLI-03'],
    prerequisites: [
      'Public network access to api.payments.enterprise.internal',
      'Unauthenticated webhook registration endpoint reachable',
      'Flat internal subnet routing between API and Redis cluster',
    ],
    impactAssessment: 'Total compromise of cardholder transaction history, bank routing numbers, and payment audit logs.',
    recommendedFixSequence: [
      'Implement strict URL whitelist validation and block internal RFC1918 & metadata IPs on WebhookService (Neutralizes Stage 1)',
      'Enable Redis requirepass authentication and restrict Redis subnet ingress (Neutralizes Stage 2)',
      'Convert LedgerRepository raw SQL concatenation to parameterized PreparedStatements (Neutralizes Stage 3)',
    ],
    status: 'active',
    participatingAssets: [
      'api.payments.enterprise.internal',
      'redis.payments.internal',
      'ledger.payments.internal',
    ],
  },
  {
    id: 'PATH-02-HIGH',
    scanId: 'SCN-SAMPLE-01',
    projectId: 'PRJ-FINTECH-CORE',
    title: 'Hardcoded JWT Secret → Admin Token Forgery → Microservice Takeover',
    summary: 'An attacker leveraging code leaks or decompiled binaries utilizes the hardcoded HMAC secret to forge administrative JWTs, bypassing API authorization checks.',
    severity: 'High',
    confidence: 'Strongly Indicated',
    contextualScore: 82,
    scoreBreakdown: {
      exposureScore: 18,
      exploitabilityScore: 23,
      assetCriticalityScore: 22,
      chainImpactScore: 19,
      bonusPenalties: 0,
      totalScore: 82,
      explanation: 'Formula: Exposure (18/25) + Exploitability (23/25) + Asset Criticality (22/25) + Chain Multiplier (19/25) = 82/100.',
    },
    nodes: [
      { id: 'node-jwt-0', label: 'External Actor', type: 'threat_actor', isEntrypoint: true },
      { id: 'node-jwt-1', label: 'Hardcoded JWT Secret', subLabel: 'CWE-798 in jwt.ts', type: 'vulnerability', findingRef: 'FND-JWT-05', severity: 'High' },
      { id: 'node-jwt-2', label: 'Auth Subsystem API', subLabel: 'auth.payments.enterprise.internal', type: 'service' },
      { id: 'node-jwt-3', label: 'Admin Management Gateway', subLabel: 'Full Tenant Controls', type: 'datastore', isTarget: true },
    ],
    edges: [
      { id: 'ej1', fromNodeId: 'node-jwt-0', toNodeId: 'node-jwt-1', relation: 'discovers', label: 'Decompile / Read Hardcoded Key', riskWeight: 20 },
      { id: 'ej2', fromNodeId: 'node-jwt-1', toNodeId: 'node-jwt-2', relation: 'forges_token_for', label: 'Forge Admin JWT Claim', riskWeight: 35 },
      { id: 'ej3', fromNodeId: 'node-jwt-2', toNodeId: 'node-jwt-3', relation: 'escalates_to', label: 'Gain Superadmin API Access', riskWeight: 30 },
    ],
    participatingFindingIds: ['FND-JWT-05'],
    prerequisites: ['Knowledge of hardcoded JWT fallback string'],
    impactAssessment: 'Unauthorized generation of valid administrative tokens for all internal payment microservices.',
    recommendedFixSequence: [
      'Rotate signing keys and enforce mandatory KMS / Vault secret injection at runtime',
      'Remove fallback strings from codebase and add CI SAST blocking rule',
    ],
    status: 'active',
    participatingAssets: [
      'auth.payments.enterprise.internal',
      'api.payments.enterprise.internal',
    ],
  },
];

export const SAMPLE_REMEDIATIONS: RemediationItem[] = [
  {
    id: 'REM-01-SSRF',
    projectId: 'PRJ-FINTECH-CORE',
    title: 'Implement Egress URL Whitelisting & Block Private IP Ranges in Webhook Dispatcher',
    priority: 'P0 - Immediate',
    affectedAsset: 'api.payments.enterprise.internal',
    engineeringAction: 'Add DNS pre-resolution and validate target IP against RFC1918, RFC6598, loopback, and AWS metadata (169.254.169.254). Disallow HTTP redirects to private hosts.',
    architecturalSafeguards: [
      'DNS Pinning / Safe HTTP Client',
      'Egress Firewall NetworkPolicy',
      'IMDSv2 Enforcement with Hop Limit = 1',
    ],
    validationRequirements: 'Verify unauthenticated requests to 169.254.169.254 and 127.0.0.1 return 400 Bad Request.',
    estimatedRiskReductionPercent: 45,
    affectedFindingIds: ['FND-SSRF-01'],
    affectedAttackPathIds: ['PATH-01-CRIT'],
    pathsEliminatedCount: 1,
    status: 'pending',
    assignedTo: 'Lead Backend Engineer',
    aiGuidance: {
      rootCauseExplanation: 'The WebhookService directly issues outbound HTTP requests to user-supplied URLs without resolving the destination IP or verifying it against private network boundaries.',
      impactRationale: 'Resolving this bottleneck breaks the initial ingress stage of the highest-rated multi-hop attack path (PATH-01-CRIT), preventing pivot into Redis and Postgres.',
      remediationBlueprint: `// Safe Webhook Dispatcher with IP Resolution Guard
import dns from 'dns/promises';
import ipaddr from 'ipaddr.js';

export async function validateWebhookUrl(rawUrl: string): Promise<boolean> {
  const parsed = new URL(rawUrl);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Unsupported protocol');
  }

  // Resolve hostname to IP before request
  const addresses = await dns.lookup(parsed.hostname, { all: true });
  for (const { address } of addresses) {
    const addr = ipaddr.parse(address);
    if (addr.range() !== 'unicast' || address === '169.254.169.254') {
      throw new Error('Access to private/internal network addresses is forbidden');
    }
  }
  return true;
}`,
      verificationSteps: [
        'Attempt to register http://169.254.169.254/ and verify immediate 400 rejection',
        'Attempt to register http://127.0.0.1:6379/ and verify socket blocked',
        'Verify legitimate external webhooks (e.g. https://api.merchant.com/webhook) succeed',
      ],
      residualRiskNotes: 'Ensure DNS rebinding protection by performing request connection directly to resolved IP with SNI header.',
    },
  },
  {
    id: 'REM-02-SQLI',
    projectId: 'PRJ-FINTECH-CORE',
    title: 'Migrate Settlement Reconciliation Queries to Parameterized PreparedStatements',
    priority: 'P0 - Immediate',
    affectedAsset: 'ledger.payments.internal',
    engineeringAction: 'Refactor string-interpolated SQL statements in LedgerRepository to use typed Prisma/TypeORM parameterized queries.',
    architecturalSafeguards: [
      'ORM Parameterization',
      'Database Least-Privilege Role',
      'WAF SQLi Signature Rule',
    ],
    validationRequirements: 'Verify single-quote SQL payload does not alter database execution tree.',
    estimatedRiskReductionPercent: 35,
    affectedFindingIds: ['FND-SQLI-03'],
    affectedAttackPathIds: ['PATH-01-CRIT'],
    pathsEliminatedCount: 1,
    status: 'pending',
    assignedTo: 'Data Engineering Lead',
    aiGuidance: {
      rootCauseExplanation: 'Dynamic string concatenation was used in LedgerRepository.ts:88 to concatenate batch_id parameter directly into SQL string.',
      impactRationale: 'Completely eliminates extraction and modification risks on the customer transaction database.',
      remediationBlueprint: `// Parameterized Database Query Pattern
import { pool } from '../db/client';

export async function getSettlementBatch(batchId: string) {
  // Use parameterized placeholders ($1) instead of template literals
  const query = 'SELECT * FROM settlement_batches WHERE batch_id = $1 AND deleted_at IS NULL';
  const { rows } = await pool.query(query, [batchId]);
  return rows[0] || null;
}`,
      verificationSteps: [
        "Send batch_id=\"1' OR '1'='1\" and verify database returns 0 rows without syntax error",
        'Run automated Semgrep SAST scan to verify CWE-89 rule passes with 0 findings',
      ],
      residualRiskNotes: 'Ensure all surrounding repositories also undergo static audit to prevent duplicate patterns.',
    },
  },
  {
    id: 'REM-03-REDIS',
    projectId: 'PRJ-FINTECH-CORE',
    title: 'Enforce Strong Redis Authentication (requirepass) & TLS Encryption',
    priority: 'P1 - High',
    affectedAsset: 'redis.payments.internal',
    engineeringAction: 'Configure redis.conf with strong 256-bit password, enable ACLs, and restrict bind interface to dedicated VPC peering subnet.',
    architecturalSafeguards: [
      'Redis AUTH / ACLs',
      'TLS in Transit',
      'VPC Security Group Isolation',
    ],
    validationRequirements: 'Verify unauthenticated redis-cli ping returns NOAUTH Authentication required.',
    estimatedRiskReductionPercent: 20,
    affectedFindingIds: ['FND-REDIS-02'],
    affectedAttackPathIds: ['PATH-01-CRIT'],
    pathsEliminatedCount: 1,
    status: 'pending',
    assignedTo: 'DevOps / Infrastructure',
  },
  {
    id: 'REM-04-JWT',
    projectId: 'PRJ-FINTECH-CORE',
    title: 'Rotate JWT Signing Secret to AWS KMS / HashiCorp Vault Managed Key',
    priority: 'P1 - High',
    affectedAsset: 'auth.payments.enterprise.internal',
    engineeringAction: 'Remove hardcoded secret fallback from code. Configure KMS asymmetric signing (RS256) with automatic key rotation.',
    architecturalSafeguards: ['Asymmetric RS256 JWTs', 'Secrets Manager Key Injection'],
    validationRequirements: 'Verify missing environment variable fails fast on startup rather than using fallback.',
    estimatedRiskReductionPercent: 18,
    affectedFindingIds: ['FND-JWT-05'],
    affectedAttackPathIds: ['PATH-02-HIGH'],
    pathsEliminatedCount: 1,
    status: 'pending',
    assignedTo: 'Auth Platform Team',
  },
];

export const SAMPLE_RAW_FILES = {
  zap: JSON.stringify({
    "@programName": "OWASP ZAP",
    "@version": "2.15.0",
    "site": [
      {
        "@name": "https://api.payments.enterprise.internal",
        "@host": "api.payments.enterprise.internal",
        "@port": "443",
        "@ssl": "true",
        "alerts": [
          {
            "pluginId": "40018",
            "alert": "Server-Side Request Forgery",
            "name": "Server-Side Request Forgery (SSRF) in Webhook Dispatcher",
            "riskcode": "3",
            "confidence": "3",
            "riskdesc": "High (High)",
            "desc": "The application allows user input to determine outbound HTTP requests.",
            "cweid": "918",
            "instances": [
              {
                "uri": "https://api.payments.enterprise.internal/api/v2/webhooks/subscribe",
                "method": "POST",
                "param": "callback_url",
                "attack": "http://169.254.169.254/latest/meta-data/",
                "evidence": "iam/security-credentials/payments-core-worker"
              }
            ]
          },
          {
            "pluginId": "10098",
            "alert": "Cross-Origin Resource Sharing (CORS) Misconfiguration",
            "name": "Overly Permissive Cross-Origin Resource Sharing (CORS)",
            "riskcode": "2",
            "confidence": "2",
            "riskdesc": "Medium (Medium)",
            "desc": "Access-Control-Allow-Origin: * combined with credentials.",
            "cweid": "942",
            "instances": [
              {
                "uri": "https://api.payments.enterprise.internal/api/v1/user/profile",
                "method": "OPTIONS",
                "evidence": "Access-Control-Allow-Origin: https://evil-attacker.com"
              }
            ]
          }
        ]
      }
    ]
  }, null, 2),

  nuclei: JSON.stringify([
    {
      "template-id": "redis-unauth-access",
      "info": {
        "name": "Unauthenticated Redis Cache Exposed on Internal Subnet",
        "severity": "high",
        "classification": { "cve-id": ["CVE-2023-36824"], "cwe-id": ["CWE-306"] }
      },
      "host": "redis.payments.internal:6379",
      "matched-at": "redis.payments.internal:6379",
      "extracted-results": ["redis_version: 7.0.11", "keyspace: db0:keys=14205"]
    },
    {
      "template-id": "aws-metadata-ssrf",
      "info": {
        "name": "AWS Metadata Service IMDSv1 Exposed via SSRF",
        "severity": "critical",
        "classification": { "cve-id": ["CVE-2024-38856"], "cwe-id": ["CWE-918"] }
      },
      "host": "api.payments.enterprise.internal",
      "matched-at": "https://api.payments.enterprise.internal/api/v2/webhooks/subscribe",
      "extracted-results": ["role-arn: payments-core-worker"]
    }
  ], null, 2),

  semgrep: JSON.stringify({
    "results": [
      {
        "check_id": "javascript.express.security.audit.sqli.node-postgres-sqli",
        "path": "src/repositories/LedgerRepository.ts",
        "start": { "line": 88, "col": 5 },
        "extra": {
          "message": "SQL Injection in Settlement Reconciliation Query",
          "severity": "ERROR",
          "metadata": { "cwe": "CWE-89", "cve": "CVE-2024-21626" },
          "lines": "const query = `SELECT * FROM settlement_batches WHERE batch_id = '${batchId}'`;"
        }
      },
      {
        "check_id": "javascript.jwt.security.jwt-hardcoded-secret",
        "path": "src/config/jwt.ts",
        "start": { "line": 14, "col": 5 },
        "extra": {
          "message": "Hardcoded Weak JWT Signing Secret in Service Configuration",
          "severity": "WARNING",
          "metadata": { "cwe": "CWE-798" },
          "lines": "const JWT_SECRET = process.env.JWT_SECRET || 'payments_secret_key_2024!';"
        }
      }
    ]
  }, null, 2),

  postFix: JSON.stringify({
    "results": [
      {
        "check_id": "javascript.jwt.security.jwt-hardcoded-secret",
        "path": "src/config/jwt.ts",
        "start": { "line": 14, "col": 5 },
        "extra": {
          "message": "Hardcoded Weak JWT Signing Secret in Service Configuration",
          "severity": "WARNING",
          "metadata": { "cwe": "CWE-798" },
          "lines": "const JWT_SECRET = process.env.JWT_SECRET || 'payments_secret_key_2024!';"
        }
      }
    ]
  }, null, 2),
};

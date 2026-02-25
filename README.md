# locust

An autonomous, multi-agent cybersecurity platform that chains together **reconnaissance**, **exploitation**, and **lateral movement** agents to automatically map, probe, and reason about an attack surface — end to end, without human guidance.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Agents](#agents)
  - [Recon Agent](#recon-agent)
  - [Exploit Agent](#exploit-agent)
  - [Lateral Movement Agent](#lateral-movement-agent)
- [Orchestrator](#orchestrator)
- [Why Agent-to-Agent Systems Are Hard](#why-agent-to-agent-systems-are-hard)
- [Use Cases](#use-cases)
- [Tech Stack](#tech-stack)
- [Setup](#setup)
- [Configuration](#configuration)
- [Running](#running)
- [API Reference](#api-reference)
- [Dashboard](#dashboard)

---

## Overview

locust is an **agent-to-agent (A2A) cybersecurity pipeline** where three specialized AI and deterministic agents hand off work to each other autonomously:

1. **Recon Agent** — maps the full attack surface of a target (ports, subdomains, endpoints, tech stack, exposed secrets, cloud misconfigs).
2. **Exploit Agent** — runs Nuclei vulnerability templates against every discovered asset and filters real findings from false positives using Gemini.
3. **Lateral Movement Agent** — a fully agentic LLM that reasons over confirmed vulnerabilities and the asset graph to construct step-by-step attack chains, pivoting through credentials, internal networks, and cloud resources.

Each agent is independently testable, runs on a protocol interface, and communicates through structured data models persisted in MongoDB. The result is a continuously running offensive intelligence system that produces actionable, evidence-backed attack chains — complete with MITRE ATT&CK mappings and optional on-chain anchoring via Solana for tamper-proof audit trails.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Orchestrator                            │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  Recon Agent │───▶│ Exploit Agent│───▶│  Lateral Agent   │  │
│  │              │    │              │    │  (Gemini A2A)    │  │
│  │  Deterministic│   │  Nuclei +    │    │  Tool calls:     │  │
│  │  + Gemini    │    │  Gemini FP   │    │  - reachability  │  │
│  │  scoring     │    │  filter      │    │  - credentials   │  │
│  └──────┬───────┘    └──────┬───────┘    │  - IAM perms     │  │
│         │                   │            │  - data stores   │  │
│         ▼                   ▼            └────────┬─────────┘  │
│      Assets DB          Findings DB               │            │
│      (MongoDB)          (MongoDB)                 ▼            │
│                                            Attack Chains DB     │
│                                            (MongoDB)           │
└──────────────────────────────┬──────────────────┬──────────────┘
                               │                  │
                    ┌──────────▼──────┐  ┌────────▼────────┐
                    │ Solana Anchor   │  │  GitHub Issues  │
                    │ (on-chain audit)│  │  (auto-triage)  │
                    └─────────────────┘  └─────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  FastAPI + Next.js  │
                    │  Real-time Dashboard│
                    └─────────────────────┘
```

Every agent emits structured events over a broadcast channel (WebSocket), enabling the dashboard to show a live feed of the entire pipeline as it runs.

---

## Agents

### Recon Agent

The Recon Agent runs a fully deterministic, nine-step pipeline to build a comprehensive picture of an engagement's attack surface. **No LLM is used in the collection loop** — every tool runs unconditionally in a fixed order. Gemini is called exactly once, at the end, to score and prioritize each asset.

**Pipeline:**

| Step | Tool | What it does |
|------|------|-------------|
| 1 | `run_nmap` | Port-scans targets across common service ports |
| 2 | `enumerate_subdomains` | DNS brute-force and cert transparency subdomain discovery |
| 3 | `crawl_endpoints` | Recursively crawls web assets for endpoints |
| 4 | `check_exposed_files` | Probes for sensitive files (`.env`, backups, admin panels) |
| 5 | `censys_lookup` | Enriches IPs with CVE data and banner services from Censys |
| 6 | `fingerprint_tech` | Identifies tech stack from HTTP headers and service banners |
| 7 | `scan_github_secrets` | Searches public GitHub commits for leaked credentials |
| 8 | `probe_cloud_resources` | Enumerates misconfigured S3 buckets and cloud storage |
| 9 | `GeminiScorer` | Scores each asset's attack surface; produces `attack_surface_score` and `score_reasoning` |

Assets are deduplicated and merged by IP or canonical URL so the downstream exploit agent sees a clean, non-redundant target list. Out-of-scope hosts defined in `forbidden_spec` are automatically filtered at every step.

Scope integrity is verified before each cycle via SHA-256 comparison against an on-chain hash (Solana), preventing tampering with engagement parameters.

---

### Exploit Agent

The Exploit Agent implements a **two-stage confidence pipeline** that minimizes both false negatives (missed real vulns) and false positives (noisy alerts).

**Stage 1 — Nuclei (deterministic):**

[Nuclei](https://github.com/projectdiscovery/nuclei) runs against every asset URL or IP from the Recon Agent, executing a broad template library (RCE, SQLi, XSS, LFI, SSRF, credential exposure, CVEs, misconfigs). Each raw finding is assigned a confidence score:

```
score = 0.5
      + severity bonus   (critical +0.30, high +0.20, medium +0.10, low -0.10)
      + 0.10 if HTTP type
      + 0.10 if matcher-name present
      + 0.20 if verified flag
      + 0.05 if >2 tags
```

Findings with `score >= 0.75` are **auto-confirmed** — no LLM needed.

**Stage 2 — Gemini FP Filter (EXP-03):**

Borderline findings (`score < 0.75`) are passed to `GeminiFPFilter`, which is given the raw evidence (HTTP request/response), the asset's tech stack, and Gemini's earlier attack surface reasoning. Gemini either:
- **Confirms** the finding (populates `gemini_reasoning` and sets `exploitable=True`)
- **Drops** it as a false positive (finding is discarded)
- **Errors** (finding is preserved as `exploitable=False` for human review)

Blast radius is tagged per finding: `multi_asset` for RCE, SQLi, SSRF, log4j, and leaked credentials; `single_asset` otherwise.

---

### Lateral Movement Agent

The Lateral Movement Agent is a **fully agentic LLM loop** powered by Gemini 2.5 Flash. It receives confirmed `multi_asset` findings and the full asset graph, then autonomously decides which tools to call — up to `MAX_TOOL_ROUNDS = 8` per finding — to construct a concrete attack chain.

**Available tools:**

| Tool | Description |
|------|-------------|
| `check_network_reachability` | TCP-probes a target host to determine lateral movement feasibility |
| `enumerate_credentials` | Parses and verifies credentials from finding evidence; attempts live DB/AWS connections |
| `check_iam_permissions` | Uses boto3 to enumerate what permissions leaked AWS credentials grant |
| `identify_sensitive_stores` | Port-scans for databases, secret managers, and admin interfaces on reachable hosts |

**Agent loop:**

1. Gemini reads the full finding JSON and asset graph, and explicitly plans its pivot strategy before issuing any tool call.
2. It calls tools iteratively: network reachability first, then credentials, then IAM, then sensitive stores.
3. When satisfied (or after `MAX_TOOL_ROUNDS`), Gemini emits a **structured JSON attack chain** using constrained generation (`response_mime_type="application/json"`, `response_schema=_LLMFinalAttackChain`).
4. A corrective retry loop repairs schema violations before giving up.

Each `AttackChain` includes:
- `entry_point` — initial compromised URL or IP
- `pivot_path` — step-by-step actions with MITRE ATT&CK IDs
- `reachable_sensitive_stores` — databases, S3 buckets, Docker sockets reachable from entry
- `blast_radius_score` — normalized 0–1 severity of full chain exploitation
- `blast_radius_summary` — executive-readable summary
- `gemini_reasoning` — full red-team reasoning trace
- `mitre_techniques` — deduplicated, inferred-where-missing MITRE IDs

Overclaims (e.g., "full access", "fully compromised") are automatically toned down unless privilege depth is explicitly proven.

---

## Orchestrator

The `Orchestrator` sequences the three agents in a single `run_cycle`:

```
run_cycle(scope)
  → recon.run(scope)                    # produces assets
  → exploit.run(eligible_assets)        # produces findings
  → lateral.run(multi_asset_findings)   # produces attack chains
  → anchor_chains(chains)               # Solana on-chain tx (optional)
  → create_issues_for_chains(chains)    # GitHub issues (optional)
```

If no `multi_asset` findings are confirmed (e.g., Nuclei found nothing), the orchestrator injects a **demo seed finding** (exposed `.env` with DB credentials) so the Lateral Agent always has something to reason about in demo/development environments.

---

## Why Agent-to-Agent Systems Are Hard

Building reliable pipelines where AI agents hand off work to each other introduces a class of problems that don't exist in single-model applications:

**1. Schema contract brittleness**

Each agent must emit and consume strictly typed data. Gemini's structured output (`response_schema`) helps, but LLMs routinely violate schemas — setting `null` where a string is required, producing markdown fences inside JSON, or using 0–10 scales instead of 0–1. Every boundary requires explicit validation, normalization, and corrective retry loops.

**2. Cascading failures**

A missed subdomain in the Recon Agent means the Exploit Agent never scans that host. A false positive that slips through becomes a spurious attack chain downstream. Errors compound — which is why each agent has independent confidence thresholds, FP filters, and fallback behaviors rather than blind trust in upstream output.

**3. Tool call coordination**

The Lateral Agent must sequence tool calls in the right order to build a coherent chain. Calling `check_iam_permissions` before `enumerate_credentials` produces empty results. The system prompt encodes a strict tool-calling strategy, but Gemini can still deviate, skip steps, or loop unnecessarily. The `MAX_TOOL_ROUNDS` cap prevents runaway token consumption.

**4. Nondeterminism at scale**

Running the same recon against the same target twice produces different assets (DNS TTL, service restarts, rate limiting). The exploit agent deduplicates findings at the MongoDB level. The lateral agent uses temperature `0.1` to reduce but not eliminate variation in chain reasoning.

**5. Context window management**

By the time the Lateral Agent reasons over a large asset graph plus all tool results, the conversation can exceed 100k tokens. Tool results are truncated, reasoning snippets are capped, and the final structured output request is issued on a separate, minimal `contents` slice to avoid hitting context limits.

**6. Trust and auditability**

Who authorized this scan? Did the scope change between cycles? Without integrity checks, an attacker could modify the engagement parameters to broaden the target list. Scope documents are SHA-256 hashed and the hash is stored on Solana's devnet, making tampering detectable. Attack chains are also anchored on-chain via SPL Memo transactions for a tamper-proof audit trail.

**7. Real-world tool fragility**

`nuclei`, `nmap`, and subdomain enumerators are external binaries that can hang, crash, time out, or produce malformed output. Every external call is wrapped with timeouts (`NUCLEI_PROCESS_TIMEOUT_S`), exit-code checks, and graceful degradation so a single broken tool doesn't abort the whole cycle.

---

## Use Cases

**Authorized penetration testing**
Security engineers define a scope (IP ranges, domains, forbidden hosts) and launch a cycle. The platform delivers a prioritized list of exploitable findings and full attack chains in minutes, rather than the hours it would take a human to run the same tools manually.

**Continuous attack surface monitoring**
Run on a schedule (the main loop sleeps 60s between cycles). Each cycle discovers new assets spun up since the last run, rescans known assets for new CVEs, and flags newly exploitable configurations — providing a living map of an organization's risk posture.

**Red team chain-of-custody**
Every finding and attack chain is timestamped and anchored on-chain. Security teams can prove to auditors exactly what was tested, when, and what was found — without relying on mutable log files or manual reports.

**Vulnerability research and CVE validation**
Point the exploit agent at a single target with specific Nuclei templates (`NUCLEI_TEMPLATES`, `NUCLEI_TAGS`) to validate whether a freshly published CVE is exploitable in a given environment. The Gemini FP filter dramatically reduces manual review time.

**Cloud misconfiguration hunting**
The recon pipeline's `probe_cloud_resources` and `scan_github_secrets` steps, combined with the lateral agent's `check_iam_permissions` tool, model the blast radius of a single leaked AWS key across all S3 buckets, EC2 instances, and Secrets Manager entries the key grants access to.

**Internal network segmentation testing**
After gaining an initial foothold via a confirmed finding, the lateral agent's `check_network_reachability` and `identify_sensitive_stores` tools map which internal services (MySQL, Redis, MongoDB, Docker socket) are reachable from the compromised host — exposing segmentation failures before a real attacker does.

**Bug bounty triage**
Integrate with a target scope via GitHub issue creation. The platform auto-files issues with full evidence (HTTP request/response), MITRE techniques, blast radius scores, and Gemini reasoning — ready for program coordinators to triage.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Agent runtime | Python 3.12, asyncio |
| LLM | Google Gemini 2.5 Flash (via `google-genai`) |
| Vulnerability scanner | Nuclei (ProjectDiscovery) |
| Port scanning | nmap (`python-nmap`) |
| Asset enrichment | Censys API |
| Database | MongoDB (async via `motor`) |
| Backend API | FastAPI + Uvicorn |
| Frontend | Next.js (React) |
| Cloud tooling | boto3 (AWS IAM/S3), PyMySQL |
| On-chain anchoring | Solana devnet (SPL Memo) via `solana`, `solders` |
| Containerization | Docker Compose |

---

## Setup

### Prerequisites

- Python 3.12+
- MongoDB (local or Atlas)
- `nuclei` binary in `PATH` ([install guide](https://github.com/projectdiscovery/nuclei#installation))
- `nmap` in `PATH`
- Node.js 18+ (for the dashboard)
- A Google Gemini API key

### Install Python dependencies

```bash
pip install -e .
```

### Install frontend dependencies

```bash
cd frontend && npm install
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

| Variable | Required | Description |
|----------|----------|-------------|
| `GEMINI_API_KEY` | Yes | Google Gemini API key for scoring, FP filtering, and lateral reasoning |
| `MONGODB_URI` | Yes | MongoDB connection string |
| `MONGODB_DB` | Yes | Database name (default: `locust-backend`) |
| `TARGET_URL` | Yes | Primary target URL for the engagement |
| `ENGAGEMENT_ID` | Yes | Unique identifier for this engagement |
| `CENSYS_API_KEY` | No | Enables CVE enrichment via Censys |
| `GITHUB_TOKEN` | No | Enables automatic GitHub issue creation from attack chains |
| `AGENT_KEYPAIR_PATH` | No | Path to Solana keypair for on-chain anchoring |
| `SOLANA_RPC_URL` | No | Solana RPC endpoint (default: devnet) |
| `NUCLEI_SEVERITY` | No | Comma-separated severity filter for Nuclei (default: all) |
| `NUCLEI_TAGS` | No | Comma-separated tag filter for Nuclei templates |
| `NUCLEI_TEMPLATES` | No | Comma-separated custom template paths |
| `LOG_LEVEL` | No | Logging verbosity (default: `INFO`) |

---

## Running

### Start a local test environment (Juice Shop + vulnerable server)

```bash
docker compose up -d
```

This starts:
- **OWASP Juice Shop** on port `3000` (pre-loaded vulnerable web app)
- **Demo vuln server** on port `8000` (exposes a `.env` file for credential exposure testing)
- **MySQL** on port `3306` (populated with the credentials from the exposed `.env`)

### Run the agent pipeline

```bash
uvicorn server.main:app --reload --port 8000
```

Or run a single headless cycle:

```bash
python -m src.main
```

### Start the dashboard

```bash
cd frontend
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000 NEXT_PUBLIC_ENGAGEMENT_ID=<your_engagement_id> npm run dev
```

---

## API Reference

All endpoints are prefixed with `/api`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/status` | Global pipeline status across all engagements |
| `GET` | `/api/assets/{engagement_id}` | All discovered assets for an engagement |
| `GET` | `/api/findings/{engagement_id}` | All confirmed findings for an engagement |
| `GET` | `/api/chains/{engagement_id}` | All attack chains for an engagement |
| `WS` | `/ws/{engagement_id}` | Real-time event stream (WebSocket) |

### Example: query assets

```bash
curl "http://localhost:8000/api/assets/my-engagement-01"
```

### Example: query attack chains

```bash
curl "http://localhost:8000/api/chains/my-engagement-01"
```

### Example: global status

```bash
curl http://localhost:8000/api/status
```

---

## Dashboard

The Next.js dashboard connects to the FastAPI backend via REST and WebSocket, showing:

- Live event feed as the pipeline runs
- Asset map with attack surface scores
- Findings table (severity, exploitability, blast radius)
- Attack chain visualizer with pivot path and MITRE techniques
- On-chain tx links for anchored chains

```bash
cd frontend
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000 NEXT_PUBLIC_ENGAGEMENT_ID=abc123 npm run dev
```

---

> **⚠️ Legal Notice:** This platform is intended exclusively for authorized security testing, red team engagements, and research on systems you own or have explicit written permission to test. Unauthorized use against systems without consent is illegal. Always operate within the boundaries of your engagement scope.


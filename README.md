# Locust

***HACKUNCP 2026 Winner: Cybersecurity Track**
Nicolas Asanov, Abhimanyu Agashe, Vidur Shah, Arya Venkatesan

An autonomous, agent-to-agent (A2A) cybersecurity platform that chains together **reconnaissance**, **exploitation**, and **lateral movement** agents to map and probe an attack surface end to end — without human guidance.

---

## Architecture

Three specialized agents run in sequence, each handing its output to the next:

```
Recon Agent ──▶ Exploit Agent ──▶ Lateral Movement Agent
    │                │                      │
 Assets DB       Findings DB          Attack Chains DB
                                            │
                              Solana on-chain anchor (optional)
                              GitHub Issues auto-triage (optional)
```

A **FastAPI** backend and **Next.js** dashboard sit in front of MongoDB, streaming live pipeline events over WebSocket as the agents run.

---

## Agents

**Recon Agent** — deterministic nine-step pipeline (port scanning, subdomain enumeration, endpoint crawling, exposed file detection, Censys CVE enrichment, tech fingerprinting, GitHub secret scanning, cloud resource probing) followed by a single Gemini call that scores each asset's attack surface.

**Exploit Agent** — runs [Nuclei](https://github.com/projectdiscovery/nuclei) vulnerability templates against every discovered asset. High-confidence findings are auto-confirmed; borderline findings are passed to Gemini for false-positive filtering. Every finding is tagged with a blast radius (`single_asset` or `multi_asset`) and MITRE ATT&CK class.

**Lateral Movement Agent** — a fully agentic Gemini 2.5 Flash loop that reasons over confirmed findings and the full asset graph. It autonomously calls tools (network reachability probing, credential enumeration, AWS IAM permission checks, sensitive data store discovery) to build concrete step-by-step attack chains with MITRE mappings and an executive blast-radius summary.

---

## What We Built

- **End-to-end autonomous pipeline** — from raw target scope to a prioritized, evidence-backed attack chain with zero manual steps between agents.
- **Gemini-powered false-positive filtering** — dramatically reduces noise from automated scanners by having the LLM review borderline findings in context.
- **Agentic lateral movement reasoning** — Gemini acts as a red team operator, deciding which tools to call and in what order to construct realistic pivot paths.
- **On-chain audit trail** — attack chains are anchored to Solana devnet via SPL Memo transactions, providing a tamper-proof record of every engagement finding.
- **Real-time dashboard** — live WebSocket event feed, asset map, findings table, and attack chain visualizer backed by FastAPI and Next.js.
- **Auto-triage GitHub issues** — confirmed attack chains are automatically filed as GitHub issues with full evidence and reasoning attached.

---

## Use Cases

- **Penetration testing** — deliver a complete set of exploitable findings and attack chains in minutes instead of hours.
- **Continuous attack surface monitoring** — run on a schedule to catch newly exposed services and CVEs as infrastructure changes.
- **Cloud misconfiguration hunting** — model the blast radius of a single leaked AWS key across S3, EC2, and Secrets Manager.
- **Bug bounty triage** — auto-file issues with HTTP evidence, MITRE techniques, and Gemini reasoning for fast program review.

---

## Running

```bash
# 1. Start local test targets (Juice Shop + demo vuln server + MySQL)
docker compose up -d

# 2. Configure environment
cp .env.example .env   # fill in GEMINI_API_KEY, MONGODB_URI, TARGET_URL, ENGAGEMENT_ID

# 3. Install dependencies
pip install -e .

# 4. Start the backend API
uvicorn server.main:app --reload --port 8000

# 5. Start the dashboard
cd frontend && npm install
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000 NEXT_PUBLIC_ENGAGEMENT_ID=<engagement_id> npm run dev
```

---

> **⚠️ Legal Notice:** This platform is intended exclusively for authorized security testing on systems you own or have explicit written permission to test.


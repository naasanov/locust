"""
github_issues.py
----------------
Creates GitHub Issues from AttackChain objects produced by the lateral agent.
Each chain becomes one issue so the engineering team has a trackable, closeable
work-item for every discovered attack path.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from src.models.attack_chain import AttackChain

_GITHUB_API = "https://api.github.com"
_SEVERITY_LABEL_MAP = [
    (0.8, "severity: critical"),
    (0.6, "severity: high"),
    (0.4, "severity: medium"),
    (0.0, "severity: low"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_nwo(repo_url: str) -> str:
    """
    Return the GitHub *name-with-owner* (``"owner/repo"``) from any of:
      - https://github.com/owner/repo
      - https://github.com/owner/repo.git
      - github.com/owner/repo
      - owner/repo   (already in NWO form)
    Raises ``ValueError`` if the URL cannot be parsed.
    """
    url = repo_url.strip().rstrip("/")

    # Already in NWO form
    if re.fullmatch(r"[^/]+/[^/]+", url):
        return url.removesuffix(".git")

    parsed = urlparse(url if "://" in url else f"https://{url}")
    # path = /owner/repo  or /owner/repo.git
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise ValueError(f"Cannot extract owner/repo from URL: {repo_url!r}")
    nwo = "/".join(parts[:2]).removesuffix(".git")
    return nwo


def _severity_label(score: float) -> str:
    for threshold, label in _SEVERITY_LABEL_MAP:
        if score >= threshold:
            return label
    return "severity: low"


def _build_issue_body(chain: AttackChain) -> str:
    """Render a Markdown issue body from an AttackChain."""

    score_pct = int(chain.blast_radius_score * 100)

    # ----- Pivot path table -----
    pivot_rows = "\n".join(
        f"| {s.step} | `{s.asset}` | `{s.action}` | {s.detail} | {s.mitre or '—'} |"
        for s in chain.pivot_path
    )
    pivot_table = (
        "| Step | Asset | Action | Detail | MITRE |\n"
        "|------|-------|--------|--------|-------|\n"
        + pivot_rows
    )

    # ----- Sensitive stores -----
    store_rows = "\n".join(
        f"- **{st.type.upper()}** `{st.asset}` — {st.contents} *(creds: `{st.credentials_used}`)*"
        for st in chain.reachable_sensitive_stores
    )
    stores_section = store_rows or "_None recorded_"

    # ----- MITRE techniques -----
    mitre_badges = " ".join(
        f"[`{t}`](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)"
        for t in chain.mitre_techniques
    )
    mitre_section = mitre_badges or "_None recorded_"

    return f"""\
## :rotating_light: Attack Chain Detected — Blast Radius {score_pct}%

> **Entry point:** `{chain.entry_point}`
> **Chain ID:** `{chain.chain_id}`
> **Engagement:** `{chain.engagement_id}`
> **Discovered:** {chain.discovered_at.strftime("%Y-%m-%d %H:%M UTC")}

---

### Blast Radius Summary

{chain.blast_radius_summary}

---

### Pivot Path

{pivot_table}

---

### Reachable Sensitive Stores

{stores_section}

---

### MITRE ATT&CK Techniques

{mitre_section}

---

### AI Reasoning

> {chain.gemini_reasoning}

---

### Metadata

| Field | Value |
|-------|-------|
| Chain ID | `{chain.chain_id}` |
| Entry Point Finding | `{chain.entry_point_finding_id}` |
| Blast Radius Score | `{chain.blast_radius_score:.2f}` |
| On-chain TX | `{chain.on_chain_tx or "—"}` |
| Discovered At | `{chain.discovered_at.isoformat()}` |

---

*Generated automatically by [UNCP](https://github.com/uncp) — please triage and close once remediated.*
"""


def _build_issue_title(chain: AttackChain) -> str:
    score_pct = int(chain.blast_radius_score * 100)
    entry = chain.entry_point
    # Truncate very long entry points cleanly
    if len(entry) > 60:
        entry = entry[:57] + "…"
    return f"[Security] Attack chain via {entry} — blast radius {score_pct}%"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def create_issues_for_chains(
    chains: list[AttackChain],
    repo_url: str,
    github_token: str,
) -> list[str]:
    """
    Open one GitHub Issue per ``AttackChain`` in *chains*.

    Parameters
    ----------
    chains:
        The list of attack chains produced by the lateral agent.
    repo_url:
        Any GitHub URL pointing to the target repo (or ``"owner/repo"``).
    github_token:
        A GitHub personal-access-token (or fine-grained token) with
        ``repo`` / ``issues:write`` scope.

    Returns
    -------
    list[str]
        The HTML URLs of every newly created issue.
    """
    if not chains:
        print("[github_issues] Skipped: no attack chains provided")
        return []
    if not github_token.strip():
        print("[github_issues] Skipped: empty github_token")
        return []

    nwo = _parse_nwo(repo_url)
    print(f"[github_issues] Starting: repo={nwo} chain_count={len(chains)}")
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    created_urls: list[str] = []

    async with httpx.AsyncClient(headers=headers, timeout=20) as client:
        # Ensure the base labels exist (best-effort, ignore errors)
        await _ensure_labels(client, nwo)

        for chain in chains:
            labels = ["security", "attack-chain", _severity_label(chain.blast_radius_score)]
            payload = {
                "title": _build_issue_title(chain),
                "body": _build_issue_body(chain),
                "labels": labels,
            }
            try:
                resp = await client.post(
                    f"{_GITHUB_API}/repos/{nwo}/issues",
                    json=payload,
                )
            except Exception as exc:
                print(
                    f"[github_issues] ERROR: issue POST raised for chain={chain.chain_id} repo={nwo}: {exc}"
                )
                continue
            if resp.status_code == 201:
                url = resp.json().get("html_url", "")
                created_urls.append(url)
                print(f"[github_issues] Created issue for chain={chain.chain_id}: {url}")
            else:
                print(
                    f"[github_issues] ERROR: failed to create issue for chain={chain.chain_id} "
                    f"status={resp.status_code} body={resp.text}"
                )

    print(
        f"[github_issues] Finished: repo={nwo} created={len(created_urls)} attempted={len(chains)}"
    )
    return created_urls


async def _ensure_labels(client: httpx.AsyncClient, nwo: str) -> None:
    """Create any missing labels used by this integration (best-effort)."""
    desired = [
        {"name": "security", "color": "d73a4a", "description": "Security vulnerability"},
        {"name": "attack-chain", "color": "e4e669", "description": "Multi-step attack path"},
        {"name": "severity: critical", "color": "b60205", "description": ""},
        {"name": "severity: high", "color": "d93f0b", "description": ""},
        {"name": "severity: medium", "color": "e99695", "description": ""},
        {"name": "severity: low", "color": "c5def5", "description": ""},
    ]
    for label in desired:
        try:
            resp = await client.post(f"{_GITHUB_API}/repos/{nwo}/labels", json=label)
            if resp.status_code in (201, 422):
                print(
                    f"[github_issues] Label ensured: repo={nwo} label={label['name']} status={resp.status_code}"
                )
            else:
                print(
                    f"[github_issues] WARNING: label ensure failed: repo={nwo} "
                    f"label={label['name']} status={resp.status_code} body={resp.text}"
                )
            # 201 = created, 422 = already exists — both are fine
        except Exception as exc:  # noqa: BLE001
            print(
                f"[github_issues] ERROR: label ensure raised: repo={nwo} "
                f"label={label['name']} err={exc}"
            )

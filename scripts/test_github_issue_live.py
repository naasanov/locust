"""
Live GitHub issue smoke test using the same integration path as Orchestrator.

This script:
1) Reads GITHUB_TOKEN from src.config.get_settings()
2) Builds a realistic AttackChain payload
3) Calls src.integrations.github_issues.create_issues_for_chains(...)
4) Prints created issue URL(s)

Usage:
  python scripts/test_github_issue_live.py --repo-url https://github.com/<owner>/<repo>
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone

from src.config import get_settings
from src.integrations.github_issues import create_issues_for_chains
from src.models.attack_chain import AttackChain, PivotStep, SensitiveStore


def _build_chain(engagement_id: str) -> AttackChain:
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%d-%H%M%S")
    return AttackChain(
        engagement_id=engagement_id,
        chain_id=f"live-gh-issue-{ts}",
        entry_point_finding_id=f"live-finding-{ts}",
        entry_point="http://127.0.0.1:3000/.env",
        pivot_path=[
            PivotStep(
                step=1,
                asset="127.0.0.1:3000",
                action="Extract Credentials",
                detail="Discovered DB_USER and DB_PASSWORD from exposed .env content.",
                mitre="T1552.001",
            ),
            PivotStep(
                step=2,
                asset="127.0.0.1:3306",
                action="Database Access",
                detail="Connected to MySQL with leaked credentials.",
                mitre="T1078",
            ),
        ],
        reachable_sensitive_stores=[
            SensitiveStore(
                type="database",
                asset="127.0.0.1:3306",
                contents="juice_db (potential user and order records)",
                credentials_used="juice_admin:s3cr3tpass!",
            )
        ],
        blast_radius_score=0.85,
        blast_radius_summary=(
            "Credential exposure enables authenticated database access and potential "
            "data exfiltration."
        ),
        gemini_reasoning=(
            "Leaked .env credentials were used to access MySQL. This creates a direct "
            "pivot from web exposure to sensitive data storage."
        ),
        on_chain_tx=None,
        mitre_techniques=["T1552.001", "T1078", "T1530"],
        discovered_at=now,
    )


async def _run(repo_url: str, engagement_id: str) -> int:
    settings = get_settings()
    token = settings.GITHUB_TOKEN.strip()
    if not token:
        print("ERROR: GITHUB_TOKEN is empty in get_settings().")
        print("Set it in your .env or shell env before running.")
        return 1

    chain = _build_chain(engagement_id=engagement_id)
    urls = await create_issues_for_chains(
        chains=[chain],
        repo_url=repo_url,
        github_token=token,
    )

    if not urls:
        print("ERROR: No issue was created. Check token scope and repo access.")
        return 2

    print("SUCCESS: Created GitHub issue(s):")
    for url in urls:
        print(f"  - {url}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a live GitHub issue via src/integrations/github_issues.py"
    )
    parser.add_argument(
        "--repo-url",
        required=True,
        help="GitHub repo URL or owner/repo",
    )
    parser.add_argument(
        "--engagement-id",
        default="manual-gh-issue-test-001",
        help="Engagement ID for the test chain payload",
    )
    args = parser.parse_args()

    import asyncio

    return asyncio.run(_run(args.repo_url, args.engagement_id))


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
Run the lateral movement agent against a live target and print the full attack chain.

Usage:
    python scripts/run_lateral_agent.py
    python scripts/run_lateral_agent.py --target http://localhost:3000 --snippet .env

Requires:
    - GEMINI_API_KEY in .env or environment
    - Juice Shop (or another target) running and reachable
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Ensure project root is on sys.path when run directly
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv

load_dotenv()

import os

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)-8s %(name)s: %(message)s",
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run LateralAgent and print attack chain")
    p.add_argument(
        "--target",
        default="http://localhost:3000",
        help="Base URL of the target (default: http://localhost:3000)",
    )
    p.add_argument(
        "--snippet",
        default=(
            "DB_HOST=localhost\n"
            "DB_USER=juice_admin\n"
            "DB_PASSWORD=s3cr3tpass!\n"
            "NODE_ENV=production\n"
        ),
        help="Response snippet containing credentials (default: fake .env for Juice Shop)",
    )
    p.add_argument(
        "--vuln-class",
        default="credential_exposure",
        dest="vuln_class",
        help="Vulnerability class (default: credential_exposure)",
    )
    p.add_argument(
        "--debug",
        action="store_true",
        help="Enable DEBUG logging (shows tool return sizes)",
    )
    p.add_argument(
        "--verbose-llm",
        action="store_true",
        default=True,
        help="Log Gemini text parts, tool call args, and tool responses per round",
    )
    return p.parse_args()


async def main() -> None:
    args = parse_args()

    if args.debug or args.verbose_llm:
        logging.getLogger().setLevel(logging.DEBUG)
        # Keep debug output focused on agent/tool behavior, not transport internals.
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("google").setLevel(logging.WARNING)

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print(
            "ERROR: GEMINI_API_KEY not set. Add it to .env or export it.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Import here so logging is configured first
    from src.models.asset import AssetDocument
    from src.models.finding import Evidence, FindingDocument, LateralAgentInput

    LateralAgentInput.model_rebuild()

    from src.agents.lateral.agent import LateralAgent

    finding = FindingDocument(
        engagement_id="script-run-001",
        asset_id="asset-target",
        finding_id="finding-script-001",
        vulnerability_class=args.vuln_class,
        title=f"{args.vuln_class.replace('_', ' ').title()} on {args.target}",
        severity="critical",
        exploitable=True,
        affected_url=f"{args.target.rstrip('/')}/.env",
        evidence=Evidence(
            request=f"GET /.env HTTP/1.1\nHost: {args.target}",
            response_snippet=args.snippet,
            status_code=200,
        ),
        blast_radius="multi_asset",
    )

    asset = AssetDocument(
        engagement_id="script-run-001",
        asset_type="web_app",
        url=args.target,
        ip="127.0.0.1",
        open_ports=[3000],
        attack_surface_score=0.85,
    )

    print(f"\nTarget:    {args.target}")
    print(f"Vuln:      {args.vuln_class}")
    print(f"Snippet:   {args.snippet[:60].strip()}...")
    print("-" * 60)

    agent = LateralAgent(api_key=api_key, verbose_llm=args.verbose_llm)
    chains = await agent.run(LateralAgentInput(findings=[finding], asset_graph=[asset]))

    print("\n" + "=" * 60)
    print(f"ATTACK CHAINS PRODUCED: {len(chains)}")
    print("=" * 60)

    if not chains:
        print("No attack chains produced — check logs above for errors.")
        sys.exit(1)

    for i, chain in enumerate(chains, 1):
        print(f"\n--- Chain {i} ---")
        print(chain.model_dump_json(indent=2))


if __name__ == "__main__":
    asyncio.run(main())

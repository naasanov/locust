"""Gemini Flash scoring for attack surface assessment."""

import os
from typing import Optional

import google.generativeai as genai

from ..models.asset import Asset


class GeminiScorer:
    """
    Uses Gemini Flash to score asset attack surface.

    This is the ONLY place an LLM is used in the recon pipeline.
    Called once at the end after all deterministic tools have run.
    """

    MODEL_NAME = "gemini-1.5-flash"

    SCORING_PROMPT = """You are a security analyst scoring the attack surface of discovered assets.

Given the following asset data, provide an attack_surface_score between 0.0 and 1.0:
- 0.0-0.3: Low risk (minimal exposed services, no known vulnerabilities)
- 0.3-0.6: Medium risk (some exposed services, common configurations)
- 0.6-0.8: High risk (sensitive endpoints, outdated versions, or known CVEs)
- 0.8-1.0: Critical risk (exposed credentials, multiple high-severity CVEs, admin panels)

Asset Data:
{asset_json}

Respond with ONLY a JSON object in this exact format:
{{"score": 0.XX, "reasoning": "Brief explanation"}}
"""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the Gemini scorer.

        Args:
            api_key: Gemini API key (defaults to GEMINI_API_KEY env var)
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not set")

        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel(self.MODEL_NAME)

    def score_asset(self, asset: Asset) -> float:
        """
        Score a single asset's attack surface.

        Args:
            asset: Asset to score

        Returns:
            Score between 0.0 and 1.0
        """
        # TODO: Implement in REC-03
        raise NotImplementedError("score_asset will be implemented in REC-03")

    def score_assets(self, assets: list[Asset]) -> list[Asset]:
        """
        Score multiple assets and return them with updated scores.

        Args:
            assets: List of assets to score

        Returns:
            Same assets with attack_surface_score populated
        """
        # TODO: Implement in REC-03
        raise NotImplementedError("score_assets will be implemented in REC-03")
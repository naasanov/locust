"""Gemini Flash scoring for attack surface assessment."""

import os

from src.models.asset import AssetDocument


class GeminiScorer:
    """
    Uses Gemini Flash to score asset attack surface.

    This is the ONLY place an LLM is used in the recon pipeline.
    Called once at the end after all deterministic tools have run.
    """

    MODEL_NAME = "gemini-2.0-flash"

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

    def __init__(self, api_key: str | None = None):
        """
        Initialize the Gemini scorer.

        Args:
            api_key: Gemini API key (defaults to GEMINI_API_KEY env var)
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not set")

        try:
            from google import genai
        except ImportError as exc:
            raise ImportError(
                "google-genai is required for Gemini scoring. "
                "Install it with: pip install google-genai"
            ) from exc

        self.client = genai.Client(api_key=self.api_key)

    async def score_asset(self, asset: AssetDocument) -> AssetDocument:
        """
        Score a single asset's attack surface.

        Args:
            asset: AssetDocument to score

        Returns:
            Same asset with attack_surface_score and score_reasoning populated
        """
        # TODO: Implement in REC-03
        raise NotImplementedError("score_asset will be implemented in REC-03")

    async def score_assets(self, assets: list[AssetDocument]) -> list[AssetDocument]:
        """
        Score multiple assets and return them with updated scores.

        Args:
            assets: List of assets to score

        Returns:
            Same assets with attack_surface_score populated
        """
        # TODO: Implement in REC-03
        raise NotImplementedError("score_assets will be implemented in REC-03")

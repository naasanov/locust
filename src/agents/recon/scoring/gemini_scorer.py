"""Gemini Flash scoring for attack surface assessment."""

import asyncio
import json
import os
import re

from src.models.asset import AssetDocument


class GeminiScorer:
    """
    Uses Gemini Flash to score asset attack surface.

    This is the ONLY place an LLM is used in the recon pipeline.
    Called once at the end after all deterministic tools have run.
    """

    MODEL_NAME = "gemini-2.0-flash"

    SCORING_PROMPT = """You are a security analyst scoring attack surface risk.

For each asset in the input list, assign a score between 0.0 and 1.0:
- 0.0-0.3: Low risk
- 0.3-0.6: Medium risk
- 0.6-0.8: High risk
- 0.8-1.0: Critical risk

Input assets JSON:
{assets_json}

Respond with ONLY valid JSON in this exact format:
[
  {{"index": 0, "score": 0.42, "reasoning": "Brief explanation"}},
  {{"index": 1, "score": 0.15, "reasoning": "Brief explanation"}}
]
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
        scored = await self.score_assets([asset])
        return scored[0]

    async def score_assets(self, assets: list[AssetDocument]) -> list[AssetDocument]:
        """
        Score multiple assets and return them with updated scores.

        Args:
            assets: List of assets to score

        Returns:
            Same assets with attack_surface_score populated
        """
        if not assets:
            return []

        assets_payload = [
            asset.model_dump(
                mode="json",
                exclude={"attack_surface_score", "score_reasoning", "discovered_at"},
            )
            for asset in assets
        ]

        prompt = self.SCORING_PROMPT.format(
            assets_json=json.dumps(assets_payload, indent=2, sort_keys=True)
        )

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self.client.models.generate_content(
                model=self.MODEL_NAME,
                contents=prompt,
            ),
        )
        text = self._extract_response_text(response)
        parsed = self._parse_scores(text, len(assets))

        for idx, asset in enumerate(assets):
            score_entry = parsed.get(idx)
            if score_entry is None:
                asset.attack_surface_score = 0.0
                asset.score_reasoning = "No score returned by Gemini."
                continue

            raw_score = score_entry.get("score", 0.0)
            try:
                score = float(raw_score)
            except (TypeError, ValueError):
                score = 0.0
            asset.attack_surface_score = max(0.0, min(1.0, score))
            asset.score_reasoning = str(
                score_entry.get("reasoning", "No reasoning provided.")
            )

        return assets

    @staticmethod
    def _extract_response_text(response: object) -> str:
        """Extract text content from google-genai response object."""
        text = getattr(response, "text", None)
        if isinstance(text, str) and text.strip():
            return text

        candidates = getattr(response, "candidates", None) or []
        parts_text: list[str] = []
        for candidate in candidates:
            content = getattr(candidate, "content", None)
            parts = getattr(content, "parts", None) or []
            for part in parts:
                part_text = getattr(part, "text", None)
                if isinstance(part_text, str):
                    parts_text.append(part_text)
        return "\n".join(parts_text)

    @staticmethod
    def _parse_scores(text: str, expected_count: int) -> dict[int, dict]:
        """Parse JSON score list from model output."""
        if not text:
            return {}

        match = re.search(r"\[[\s\S]*\]", text)
        payload = match.group(0) if match else text

        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return {}

        if not isinstance(data, list):
            return {}

        parsed: dict[int, dict] = {}
        for item in data:
            if not isinstance(item, dict):
                continue
            idx = item.get("index")
            if not isinstance(idx, int):
                continue
            if idx < 0 or idx >= expected_count:
                continue
            parsed[idx] = item
        return parsed

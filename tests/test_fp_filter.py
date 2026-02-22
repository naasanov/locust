"""
Direct unit tests for GeminiFPFilter — EXP-03.

Covers:
  - _parse_verdict edge cases
  - malformed false_positive_risk values
  - API exception propagation (no silent FP drop)
  - genuine FP verdict (confirmed=false)
  - confirmed verdict with adjusted severity
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.agents.exploit.fp_filter import (
    GeminiFPFilter,
    _extract_text,
    _normalize_severity,
    _parse_verdict,
)
from src.models.asset import AssetDocument
from src.models.finding import Evidence, FindingDocument


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_finding(**kwargs) -> FindingDocument:
    # Build with explicit defaults, allowing overrides
    return FindingDocument(
        engagement_id=kwargs.get("engagement_id", "eng-test"),
        asset_id=kwargs.get("asset_id", "asset-123"),
        finding_id=kwargs.get("finding_id", "finding-456"),
        vulnerability_class=kwargs.get("vulnerability_class", "xss"),
        title=kwargs.get("title", "Reflected XSS"),
        severity=kwargs.get("severity", "medium"),  # type: ignore[arg-type]
        exploitable=kwargs.get("exploitable", False),
        affected_url=kwargs.get("affected_url", "http://example.com/search?q=1"),
        evidence=kwargs.get(
            "evidence",
            Evidence(
                request="GET /search?q=<script> HTTP/1.1",
                response_snippet="HTTP/1.1 200 OK\n\n<script>",
                status_code=200,
            ),
        ),
        blast_radius=kwargs.get("blast_radius", "single_asset"),  # type: ignore[arg-type]
        credentials_found=kwargs.get("credentials_found", []),
        gemini_reasoning=kwargs.get("gemini_reasoning"),
        on_chain_tx=kwargs.get("on_chain_tx"),
        remediation=kwargs.get("remediation"),
        mitre_technique=kwargs.get("mitre_technique"),
        discovered_at=kwargs.get("discovered_at") or FindingDocument.model_fields["discovered_at"].default_factory(),  # type: ignore[misc]
    )


def _make_filter(api_key: str = "test-key") -> GeminiFPFilter:
    with patch("google.genai.Client"):
        with patch("src.agents.exploit.fp_filter.GeminiFPFilter.__init__", return_value=None):
            f = GeminiFPFilter.__new__(GeminiFPFilter)
            f.api_key = api_key
            f.client = MagicMock()
            return f


# ---------------------------------------------------------------------------
# _parse_verdict
# ---------------------------------------------------------------------------


class TestParseVerdict:
    def test_valid_json(self):
        text = '{"confirmed": true, "reasoning": "Real finding.", "adjusted_severity": "high", "false_positive_risk": 0.1}'
        result = _parse_verdict(text)
        assert result is not None
        assert result["confirmed"] is True
        assert result["adjusted_severity"] == "high"

    def test_json_wrapped_in_markdown(self):
        text = '```json\n{"confirmed": false, "reasoning": "FP.", "adjusted_severity": "info", "false_positive_risk": 0.9}\n```'
        result = _parse_verdict(text)
        assert result is not None
        assert result["confirmed"] is False

    def test_json_with_surrounding_prose(self):
        text = 'Here is my analysis:\n{"confirmed": true, "reasoning": "Valid.", "adjusted_severity": "medium", "false_positive_risk": 0.2}\nEnd.'
        result = _parse_verdict(text)
        assert result is not None
        assert result["confirmed"] is True

    def test_empty_string_returns_none(self):
        assert _parse_verdict("") is None

    def test_plain_prose_returns_none(self):
        assert _parse_verdict("This is definitely a false positive.") is None

    def test_json_array_returns_none(self):
        """A JSON array (not dict) should return None."""
        assert _parse_verdict('[{"confirmed": true}]') is None

    def test_partial_json_returns_none(self):
        assert _parse_verdict('{"confirmed": true') is None


# ---------------------------------------------------------------------------
# _normalize_severity
# ---------------------------------------------------------------------------


class TestNormalizeSeverityFPFilter:
    def test_valid_severities(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            assert _normalize_severity(sev) == sev

    def test_unknown_defaults_to_medium(self):
        assert _normalize_severity("severe") == "medium"
        assert _normalize_severity("") == "medium"
        assert _normalize_severity(None) == "medium"  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _extract_text
# ---------------------------------------------------------------------------


class TestExtractText:
    def test_direct_text_attribute(self):
        response = MagicMock()
        response.text = "  some text  "
        assert _extract_text(response) == "  some text  "

    def test_falls_back_to_candidates(self):
        response = MagicMock()
        response.text = None
        part = MagicMock()
        part.text = "candidate text"
        content = MagicMock()
        content.parts = [part]
        candidate = MagicMock()
        candidate.content = content
        response.candidates = [candidate]
        assert _extract_text(response) == "candidate text"

    def test_returns_empty_when_nothing(self):
        response = MagicMock()
        response.text = None
        response.candidates = []
        assert _extract_text(response) == ""


# ---------------------------------------------------------------------------
# GeminiFPFilter.filter — malformed false_positive_risk
# ---------------------------------------------------------------------------


class TestFPFilterMalformedRisk:
    @pytest.mark.asyncio
    async def test_non_numeric_fp_risk_does_not_crash(self):
        """Malformed false_positive_risk must not raise ValueError."""
        finding = _make_finding()
        f = _make_filter()

        good_json = '{"confirmed": true, "reasoning": "Real.", "adjusted_severity": "medium", "false_positive_risk": "not-a-number"}'
        mock_response = MagicMock()
        mock_response.text = good_json

        with patch(
            "src.agents.exploit.fp_filter.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=mock_response)
            result = await f.filter(finding)

        # Should still return the confirmed finding despite bad fp_risk
        assert result is not None
        assert result.exploitable is True

    @pytest.mark.asyncio
    async def test_null_fp_risk_does_not_crash(self):
        """null false_positive_risk must not raise TypeError."""
        finding = _make_finding()
        f = _make_filter()

        good_json = '{"confirmed": false, "reasoning": "FP.", "adjusted_severity": "info", "false_positive_risk": null}'
        mock_response = MagicMock()
        mock_response.text = good_json

        with patch(
            "src.agents.exploit.fp_filter.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=mock_response)
            result = await f.filter(finding)

        assert result is None  # confirmed=false → FP drop


# ---------------------------------------------------------------------------
# GeminiFPFilter.filter — API exception propagation
# ---------------------------------------------------------------------------


class TestFPFilterExceptionPropagation:
    @pytest.mark.asyncio
    async def test_api_exception_raises_not_returns_none(self):
        """
        API/network errors must raise, not return None.
        Callers (agent.py) distinguish errors from genuine FP drops.
        """
        finding = _make_finding()
        f = _make_filter()

        with patch(
            "src.agents.exploit.fp_filter.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(
                side_effect=RuntimeError("429 RESOURCE_EXHAUSTED")
            )
            with pytest.raises(RuntimeError, match="429 RESOURCE_EXHAUSTED"):
                await f.filter(finding)

    @pytest.mark.asyncio
    async def test_unparseable_response_raises_not_returns_none(self):
        """
        If Gemini returns prose instead of JSON, filter must raise RuntimeError,
        not silently treat it as a false positive.
        """
        finding = _make_finding()
        f = _make_filter()

        mock_response = MagicMock()
        mock_response.text = "I think this is probably a false positive due to WAF noise."

        with patch(
            "src.agents.exploit.fp_filter.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=mock_response)
            with pytest.raises(RuntimeError, match="Unparseable Gemini verdict"):
                await f.filter(finding)


# ---------------------------------------------------------------------------
# GeminiFPFilter.filter — genuine FP and confirmed paths
# ---------------------------------------------------------------------------


class TestFPFilterVerdicts:
    @pytest.mark.asyncio
    async def test_confirmed_true_returns_finding(self):
        finding = _make_finding()
        f = _make_filter()

        mock_response = MagicMock()
        mock_response.text = '{"confirmed": true, "reasoning": "Script tag in response.", "adjusted_severity": "high", "false_positive_risk": 0.05}'

        with patch(
            "src.agents.exploit.fp_filter.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=mock_response)
            result = await f.filter(finding)

        assert result is not None
        assert result.exploitable is True
        assert result.severity == "high"
        assert result.gemini_reasoning is not None
        assert "Script tag" in result.gemini_reasoning

    @pytest.mark.asyncio
    async def test_confirmed_false_returns_none(self):
        finding = _make_finding()
        f = _make_filter()

        mock_response = MagicMock()
        mock_response.text = '{"confirmed": false, "reasoning": "WAF blocked, likely FP.", "adjusted_severity": "info", "false_positive_risk": 0.92}'

        with patch(
            "src.agents.exploit.fp_filter.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.run_in_executor = AsyncMock(return_value=mock_response)
            result = await f.filter(finding)

        assert result is None  # genuine FP — drop


# ---------------------------------------------------------------------------
# agent.py error-handling integration
# ---------------------------------------------------------------------------


class TestAgentFilterErrorHandling:
    """
    Verify that when GeminiFPFilter.filter() raises, agent.py keeps the finding
    as borderline (exploitable=False) instead of silently dropping it.
    """

    @pytest.mark.asyncio
    async def test_filter_error_keeps_finding_as_borderline(self):
        import json
        from unittest.mock import patch, AsyncMock, MagicMock
        from src.agents.exploit.agent import ExploitAgent
        from src.models.asset import AssetDocument

        agent = ExploitAgent(gemini_api_key="test-key")

        assets = [
            AssetDocument(
                engagement_id="eng-test",
                asset_type="web_app",
                url="http://example.com",
            )
        ]

        # Low-confidence finding → will go to borderline
        mock_nuclei_output = json.dumps({
            "template-id": "info-disclosure",
            "info": {
                "name": "Info Disclosure",
                "severity": "info",
                "tags": ["exposure"],
                "verified": False,
            },
            "type": "http",
            "matched-at": "http://example.com",
            "request": "GET / HTTP/1.1",
            "response": "HTTP/1.1 200 OK\n\n",
        })

        with patch("shutil.which", return_value="/usr/bin/nuclei"):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate = AsyncMock(
                    return_value=(mock_nuclei_output.encode(), b"")
                )
                mock_process.returncode = 0
                mock_exec.return_value = mock_process

                with patch("src.agents.exploit.agent.GeminiFPFilter") as mock_cls:
                    mock_filter = MagicMock()
                    mock_filter.filter = AsyncMock(
                        side_effect=RuntimeError("429 RESOURCE_EXHAUSTED")
                    )
                    mock_cls.return_value = mock_filter

                    findings = await agent.run(assets)

                # Finding is kept (not silently dropped)
                assert len(findings) == 1
                kept = findings[0]
                assert kept.exploitable is False  # not confirmed
                assert kept.gemini_reasoning is not None
                assert "filter-error" in kept.gemini_reasoning
                assert "429" in kept.gemini_reasoning

"""
Unit tests for src/integrations/github_issues.py

Coverage:
  - _parse_nwo: all supported URL forms + invalid inputs
  - _severity_label: boundary scores
  - _build_issue_title: normal + truncation
  - _build_issue_body: key sections present + empty stores / empty MITRE
  - create_issues_for_chains:
      - empty chain list → no HTTP calls
      - successful creation → returns URLs
      - HTTP error → skipped gracefully, other chains still processed
      - label pre-creation (422 already-exists treated as OK)
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.integrations.github_issues import (
    _build_issue_body,
    _build_issue_title,
    _parse_nwo,
    _severity_label,
    create_issues_for_chains,
)
from src.models.attack_chain import AttackChain, PivotStep, SensitiveStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_FIXED_TS = datetime(2026, 2, 21, 23, 2, 17, tzinfo=timezone.utc)


def _make_chain(**kwargs) -> AttackChain:
    defaults = dict(
        engagement_id="abc123",
        chain_id="chain-0041",
        entry_point_finding_id="f-8821",
        entry_point="https://dev-portal.acmecorp.com/.env.backup",
        pivot_path=[
            PivotStep(
                step=1,
                asset="dev-portal.acmecorp.com",
                action="credential_harvested",
                detail="AWS key extracted from .env.backup",
                mitre="T1552.001",
            ),
            PivotStep(
                step=2,
                asset="aws://acmecorp-prod",
                action="iam_enumeration",
                detail="AWS key has iam:ListRoles",
                mitre="T1078.004",
            ),
        ],
        reachable_sensitive_stores=[
            SensitiveStore(
                type="database",
                asset="internal-db.acmecorp.com",
                contents="847,000 customer PII records",
                credentials_used="DB_PASSWORD from .env.backup",
            ),
        ],
        blast_radius_score=0.89,
        blast_radius_summary="Single exposed .env.backup grants full DB access.",
        gemini_reasoning="Overpermissioned IAM key + exposed DB cred = critical.",
        on_chain_tx="9Kp2z...sig",
        mitre_techniques=["T1552.001", "T1078.004", "T1555"],
        discovered_at=_FIXED_TS,
    )
    defaults.update(kwargs)
    return AttackChain(**defaults)


# ---------------------------------------------------------------------------
# _parse_nwo
# ---------------------------------------------------------------------------

class TestParseNwo:
    def test_full_https_url(self):
        assert _parse_nwo("https://github.com/owner/repo") == "owner/repo"

    def test_full_https_url_with_git_suffix(self):
        assert _parse_nwo("https://github.com/owner/repo.git") == "owner/repo"

    def test_url_without_scheme(self):
        assert _parse_nwo("github.com/owner/repo") == "owner/repo"

    def test_already_nwo(self):
        assert _parse_nwo("owner/repo") == "owner/repo"

    def test_trailing_slash_stripped(self):
        assert _parse_nwo("https://github.com/owner/repo/") == "owner/repo"

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError):
            _parse_nwo("https://github.com/onlyone")

    def test_bare_domain_raises(self):
        with pytest.raises(ValueError):
            _parse_nwo("github.com")


# ---------------------------------------------------------------------------
# _severity_label
# ---------------------------------------------------------------------------

class TestSeverityLabel:
    @pytest.mark.parametrize(
        "score, expected",
        [
            (1.0, "severity: critical"),
            (0.8, "severity: critical"),
            (0.79, "severity: high"),
            (0.6, "severity: high"),
            (0.59, "severity: medium"),
            (0.4, "severity: medium"),
            (0.39, "severity: low"),
            (0.0, "severity: low"),
        ],
    )
    def test_boundaries(self, score: float, expected: str):
        assert _severity_label(score) == expected


# ---------------------------------------------------------------------------
# _build_issue_title
# ---------------------------------------------------------------------------

class TestBuildIssueTitle:
    def test_normal_entry_point(self):
        chain = _make_chain(entry_point="https://example.com/.env", blast_radius_score=0.89)
        title = _build_issue_title(chain)
        assert "[Security]" in title
        assert "https://example.com/.env" in title
        assert "89%" in title

    def test_long_entry_point_truncated(self):
        long_url = "https://example.com/" + "x" * 80
        chain = _make_chain(entry_point=long_url)
        title = _build_issue_title(chain)
        # Must not exceed 60-char entry display
        assert "…" in title
        # Title itself should be reasonable
        assert len(title) < 150

    def test_exactly_60_char_entry_not_truncated(self):
        entry = "https://example.com/" + "a" * 40  # 60 chars exactly
        chain = _make_chain(entry_point=entry)
        title = _build_issue_title(chain)
        assert "…" not in title


# ---------------------------------------------------------------------------
# _build_issue_body
# ---------------------------------------------------------------------------

class TestBuildIssueBody:
    def test_contains_entry_point(self):
        chain = _make_chain()
        body = _build_issue_body(chain)
        assert chain.entry_point in body

    def test_contains_blast_radius_summary(self):
        chain = _make_chain()
        body = _build_issue_body(chain)
        assert chain.blast_radius_summary in body

    def test_contains_pivot_steps(self):
        chain = _make_chain()
        body = _build_issue_body(chain)
        assert "credential_harvested" in body
        assert "T1552.001" in body

    def test_contains_sensitive_stores(self):
        chain = _make_chain()
        body = _build_issue_body(chain)
        assert "DATABASE" in body
        assert "847,000 customer PII records" in body

    def test_contains_mitre_links(self):
        chain = _make_chain()
        body = _build_issue_body(chain)
        assert "attack.mitre.org" in body
        assert "T1552" in body

    def test_gemini_reasoning_present(self):
        chain = _make_chain()
        body = _build_issue_body(chain)
        assert chain.gemini_reasoning in body

    def test_empty_stores_fallback(self):
        chain = _make_chain(reachable_sensitive_stores=[])
        body = _build_issue_body(chain)
        assert "_None recorded_" in body

    def test_empty_mitre_fallback(self):
        chain = _make_chain(mitre_techniques=[])
        body = _build_issue_body(chain)
        # Should render the fallback at least once (stores section may also be None)
        assert "_None recorded_" in body

    def test_no_on_chain_tx_renders_dash(self):
        chain = _make_chain(on_chain_tx=None)
        body = _build_issue_body(chain)
        assert "| On-chain TX | `—` |" in body

    def test_score_percentage_in_header(self):
        chain = _make_chain(blast_radius_score=0.89)
        body = _build_issue_body(chain)
        assert "89%" in body


# ---------------------------------------------------------------------------
# create_issues_for_chains  (async, mocked HTTP)
# ---------------------------------------------------------------------------

def _mock_response(status_code: int, json_body: dict | None = None) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    resp.text = str(json_body)
    return resp


@pytest.mark.asyncio
class TestCreateIssuesForChains:
    async def test_empty_chains_returns_empty_list(self):
        urls = await create_issues_for_chains(
            chains=[], repo_url="owner/repo", github_token="tok"
        )
        assert urls == []

    async def test_successful_creation_returns_url(self):
        chain = _make_chain()
        issue_url = "https://github.com/owner/repo/issues/1"

        mock_client = AsyncMock()
        # Labels pre-creation: always 201
        mock_client.post.side_effect = [
            _mock_response(201),  # label 1
            _mock_response(201),  # label 2
            _mock_response(201),  # label 3
            _mock_response(201),  # label 4
            _mock_response(201),  # label 5
            _mock_response(201),  # label 6
            _mock_response(201, {"html_url": issue_url}),  # actual issue
        ]

        with patch("src.integrations.github_issues.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            urls = await create_issues_for_chains(
                chains=[chain],
                repo_url="https://github.com/owner/repo",
                github_token="ghp_fake",
            )

        assert urls == [issue_url]

    async def test_http_error_skipped_gracefully(self):
        chain = _make_chain()

        mock_client = AsyncMock()
        mock_client.post.side_effect = [
            _mock_response(201),  # labels (6 calls)
            _mock_response(201),
            _mock_response(201),
            _mock_response(201),
            _mock_response(201),
            _mock_response(201),
            _mock_response(422, {"message": "Unprocessable"}),  # issue POST fails
        ]

        with patch("src.integrations.github_issues.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            urls = await create_issues_for_chains(
                chains=[chain],
                repo_url="owner/repo",
                github_token="ghp_fake",
            )

        # No URL returned, but no exception raised
        assert urls == []

    async def test_multiple_chains_all_created(self):
        chains = [_make_chain(chain_id=f"chain-{i}") for i in range(3)]
        issue_urls = [f"https://github.com/owner/repo/issues/{i+1}" for i in range(3)]

        # 6 label calls + 3 issue calls = 9 total
        label_responses = [_mock_response(422)] * 6  # already exist
        issue_responses = [
            _mock_response(201, {"html_url": u}) for u in issue_urls
        ]

        mock_client = AsyncMock()
        mock_client.post.side_effect = label_responses + issue_responses

        with patch("src.integrations.github_issues.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            urls = await create_issues_for_chains(
                chains=chains,
                repo_url="owner/repo",
                github_token="ghp_fake",
            )

        assert urls == issue_urls

    async def test_correct_labels_attached_to_critical_chain(self):
        chain = _make_chain(blast_radius_score=0.95)

        captured_payloads: list[dict] = []

        async def fake_post(url: str, json: dict | None = None, **_kw):
            if json:
                captured_payloads.append(json)
            # Distinguish label calls (have "color") from issue calls (have "title")
            if "title" in (json or {}):
                return _mock_response(201, {"html_url": "https://github.com/owner/repo/issues/99"})
            return _mock_response(201)

        mock_client = AsyncMock()
        mock_client.post.side_effect = fake_post

        with patch("src.integrations.github_issues.httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            await create_issues_for_chains(
                chains=[chain],
                repo_url="owner/repo",
                github_token="ghp_fake",
            )

        issue_payload = next(p for p in captured_payloads if "labels" in p)
        assert "severity: critical" in issue_payload["labels"]
        assert "security" in issue_payload["labels"]
        assert "attack-chain" in issue_payload["labels"]

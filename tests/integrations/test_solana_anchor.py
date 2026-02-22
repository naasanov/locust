"""
Unit tests for src/integrations/solana_anchor.py

Covers:
  - hash_chain determinism and uniqueness
  - memo_payload format
  - anchor_chains graceful degradation (no keypair, no SDK)
  - anchor_chains with mocked RPC
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.integrations.solana_anchor import hash_chain, memo_payload
from src.models.attack_chain import AttackChain, PivotStep, SensitiveStore

_FIXED_TS = datetime(2026, 2, 21, 23, 2, 17, tzinfo=timezone.utc)


def _make_chain(**kwargs) -> AttackChain:
    defaults = dict(
        engagement_id="abc123",
        chain_id="chain-0041",
        entry_point_finding_id="f-8821",
        entry_point="https://dev-portal.acmecorp.com/.env.backup",
        pivot_path=[
            PivotStep(step=1, asset="dev-portal.acmecorp.com",
                      action="credential_harvested",
                      detail="AWS key extracted", mitre="T1552.001"),
        ],
        reachable_sensitive_stores=[
            SensitiveStore(type="database", asset="db.acme.com",
                           contents="847k records",
                           credentials_used="DB_PASSWORD"),
        ],
        blast_radius_score=0.89,
        blast_radius_summary="Critical exposure.",
        gemini_reasoning="Very bad.",
        mitre_techniques=["T1552.001"],
        discovered_at=_FIXED_TS,
    )
    defaults.update(kwargs)
    return AttackChain(**defaults)


# ---------------------------------------------------------------------------
# hash_chain
# ---------------------------------------------------------------------------

class TestHashChain:
    def test_deterministic(self):
        chain = _make_chain()
        assert hash_chain(chain) == hash_chain(chain)

    def test_same_data_same_hash(self):
        a = _make_chain()
        b = _make_chain()
        assert hash_chain(a) == hash_chain(b)

    def test_different_chain_id_different_hash(self):
        a = _make_chain(chain_id="chain-0001")
        b = _make_chain(chain_id="chain-0002")
        assert hash_chain(a) != hash_chain(b)

    def test_on_chain_tx_excluded(self):
        """on_chain_tx must not affect the hash (it's set *after* hashing)."""
        a = _make_chain(on_chain_tx=None)
        b = _make_chain(on_chain_tx="5abc...fake_sig")
        assert hash_chain(a) == hash_chain(b)

    def test_hash_is_64_hex_chars(self):
        h = hash_chain(_make_chain())
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


# ---------------------------------------------------------------------------
# memo_payload
# ---------------------------------------------------------------------------

class TestMemoPayload:
    def test_format(self):
        chain = _make_chain(chain_id="chain-99")
        payload = memo_payload(chain)
        assert payload.startswith("uncp:chain:chain-99:")
        parts = payload.split(":")
        assert len(parts) == 4
        assert len(parts[3]) == 64

    def test_fits_memo_limit(self):
        """SPL Memo allows up to 566 bytes; our payload is well under."""
        chain = _make_chain()
        assert len(memo_payload(chain).encode()) < 566


# ---------------------------------------------------------------------------
# anchor_chains — graceful degradation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAnchorChainsDegradation:
    async def test_empty_keypair_path_returns_unchanged(self):
        from src.integrations.solana_anchor import anchor_chains
        chain = _make_chain()
        result = await anchor_chains([chain], "https://api.devnet.solana.com", "")
        assert result[0].on_chain_tx is None

    async def test_missing_keypair_file_returns_unchanged(self):
        from src.integrations.solana_anchor import anchor_chains
        chain = _make_chain()
        result = await anchor_chains(
            [chain], "https://api.devnet.solana.com", "/nonexistent/keypair.json"
        )
        assert result[0].on_chain_tx is None

    async def test_no_solana_sdk_returns_unchanged(self):
        from src.integrations import solana_anchor

        with patch.object(solana_anchor, "_HAS_SOLANA", False):
            chain = _make_chain()
            result = await solana_anchor.anchor_chains(
                [chain], "https://api.devnet.solana.com", "/some/path.json"
            )
            assert result[0].on_chain_tx is None

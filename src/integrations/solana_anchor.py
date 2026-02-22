"""
solana_anchor.py
----------------
Anchors AttackChain hashes on Solana using the SPL Memo Program.

Each chain is SHA-256 hashed (deterministic JSON serialisation) and submitted
as a Memo instruction.  The resulting transaction signature is stored in the
chain's ``on_chain_tx`` field, giving tamper-proof, publicly verifiable proof
of discovery time.

If the ``solana`` / ``solders`` packages are not installed, or no keypair is
configured, the module degrades gracefully — chains are returned unchanged.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from src.models.attack_chain import AttackChain

logger = logging.getLogger(__name__)

# Lazy-import guard — keeps the rest of the app running when the Solana
# SDK is not installed.
try:
    from solders.keypair import Keypair  # type: ignore[import-untyped]
    from solders.pubkey import Pubkey  # type: ignore[import-untyped]
    from solders.instruction import Instruction  # type: ignore[import-untyped]
    from solders.message import Message  # type: ignore[import-untyped]
    from solders.transaction import Transaction  # type: ignore[import-untyped]
    from solana.rpc.async_api import AsyncClient  # type: ignore[import-untyped]
    from solana.rpc.commitment import Confirmed  # type: ignore[import-untyped]
    from solana.rpc.types import TxOpts  # type: ignore[import-untyped]

    _HAS_SOLANA = True
except ImportError:  # pragma: no cover
    _HAS_SOLANA = False

# SPL Memo Program v2
_MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def hash_chain(chain: AttackChain) -> str:
    """
    Return a deterministic SHA-256 hex digest of *chain*.

    The ``on_chain_tx`` field is excluded so the hash is stable before and
    after anchoring.
    """
    data = chain.model_dump(mode="json", exclude={"on_chain_tx"})
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def memo_payload(chain: AttackChain) -> str:
    """Build the UTF-8 memo string submitted on-chain."""
    return f"uncp:chain:{chain.chain_id}:{hash_chain(chain)}"


# ---------------------------------------------------------------------------
# Keypair loading
# ---------------------------------------------------------------------------

def _load_keypair(path: str) -> "Keypair | None":
    """Load a Solana keypair from a JSON byte-array file (same format as
    ``solana-keygen``).  Returns ``None`` on any failure."""
    if not _HAS_SOLANA:
        return None
    try:
        raw = Path(path).read_text()
        secret = bytes(json.loads(raw))
        return Keypair.from_bytes(secret)
    except Exception:
        logger.warning("Could not load Solana keypair from %s", path)
        return None


# ---------------------------------------------------------------------------
# Transaction helpers
# ---------------------------------------------------------------------------

def _build_memo_ix(payload: str, signer: "Pubkey") -> "Instruction":
    """Create an SPL Memo v2 instruction."""
    return Instruction(
        program_id=Pubkey.from_string(_MEMO_PROGRAM_ID),
        accounts=[],
        data=payload.encode(),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def anchor_chains(
    chains: list[AttackChain],
    rpc_url: str,
    keypair_path: str,
) -> list[AttackChain]:
    """
    Submit a Memo transaction for each chain and populate ``on_chain_tx``.

    If the Solana SDK is missing or the keypair cannot be loaded the chains
    are returned *unchanged* — no exception is raised.
    """
    if not _HAS_SOLANA:
        logger.warning("solana/solders not installed; skipping on-chain anchoring.")
        return chains

    if not keypair_path:
        logger.warning("AGENT_KEYPAIR_PATH is empty; skipping on-chain anchoring.")
        return chains

    kp = _load_keypair(keypair_path)
    if kp is None:
        return chains

    client = AsyncClient(rpc_url)
    try:
        for chain in chains:
            try:
                payload = memo_payload(chain)
                ix = _build_memo_ix(payload, kp.pubkey())

                # Fetch a recent blockhash
                bh_resp = await client.get_latest_blockhash(commitment=Confirmed)
                blockhash = bh_resp.value.blockhash

                msg = Message.new_with_blockhash([ix], kp.pubkey(), blockhash)
                tx = Transaction.new_unsigned(msg)
                tx.sign([kp], blockhash)

                # Skip preflight to avoid devnet simulation timing issues
                resp = await client.send_transaction(tx, opts=TxOpts(skip_preflight=True))
                sig = str(resp.value)
                chain.on_chain_tx = sig
                logger.info(
                    "Anchored chain %s → tx %s",
                    chain.chain_id,
                    sig,
                )
            except Exception:
                logger.exception("Failed to anchor chain %s", chain.chain_id)
    finally:
        await client.close()

    return chains


async def verify_chain_hash(
    chain: AttackChain,
    rpc_url: str,
) -> bool:
    """
    Fetch the Memo data from a confirmed transaction and compare it against
    the locally computed hash.

    Returns ``True`` if the hashes match, ``False`` otherwise.
    """
    if not _HAS_SOLANA:
        logger.warning("solana/solders not installed; cannot verify.")
        return False

    if not chain.on_chain_tx:
        return False

    expected = memo_payload(chain)
    client = AsyncClient(rpc_url)
    try:
        from solders.signature import Signature  # type: ignore[import-untyped]

        sig = Signature.from_string(chain.on_chain_tx)
        resp = await client.get_transaction(sig, commitment=Confirmed)
        if resp.value is None:
            logger.warning("Transaction %s not found on-chain.", chain.on_chain_tx)
            return False

        log_messages = resp.value.transaction.meta.log_messages or []
        for log in log_messages:
            if expected in log:
                logger.info("Chain %s hash verified on-chain.", chain.chain_id)
                return True

        logger.warning(
            "Chain %s hash mismatch — memo payload not found in tx logs.",
            chain.chain_id,
        )
        return False
    except Exception:
        logger.exception("Error verifying chain %s", chain.chain_id)
        return False
    finally:
        await client.close()

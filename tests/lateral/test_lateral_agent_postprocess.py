from src.agents.lateral.agent import (
    _normalize_mitre_techniques,
    _sanitize_claim_language,
)
from src.models.attack_chain import PivotStep, SensitiveStore


def test_normalize_mitre_backfills_missing_step_and_includes_data_access():
    pivot_path = [
        PivotStep(
            step=1,
            asset="http://localhost:3000",
            action="Credential Exposure",
            detail="Exposed .env with DB_PASSWORD secret.",
            mitre="T1552.001",
        ),
        PivotStep(
            step=2,
            asset="localhost:3306",
            action="Database Access",
            detail="Using credentials, connected to mysql database.",
            mitre=None,
        ),
    ]
    stores = [
        SensitiveStore(
            type="database",
            asset="localhost:3306",
            contents="juice_db",
            credentials_used="juice_admin:s3cr3tpass!",
        )
    ]

    techniques = _normalize_mitre_techniques(
        pivot_path=pivot_path,
        mitre_techniques=["T1552.001"],
        reachable_sensitive_stores=stores,
    )

    assert pivot_path[1].mitre == "T1078"
    assert "T1552.001" in techniques
    assert "T1078" in techniques
    assert "T1530" in techniques


def test_sanitize_claim_language_reduces_overclaims():
    text = "Attacker gained full access and full compromise of the database."
    sanitized = _sanitize_claim_language(text)

    assert "full access" not in sanitized.lower()
    assert "full compromise" not in sanitized.lower()
    assert "authenticated access" in sanitized.lower()

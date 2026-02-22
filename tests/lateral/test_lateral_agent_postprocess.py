from src.agents.lateral.agent import (
    LateralAgent,
    _normalize_mitre_techniques,
    _sanitize_claim_language,
)
from src.models.finding import Evidence, FindingDocument
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


def test_parse_attack_chain_rejects_null_credentials_used():
    finding = FindingDocument(
        engagement_id="eng-1",
        asset_id="asset-1",
        finding_id="finding-1",
        vulnerability_class="api",
        title="Swagger exposed",
        severity="medium",
        exploitable=True,
        affected_url="http://localhost:3000/api-docs/swagger.yaml",
        evidence=Evidence(
            request="GET /api-docs/swagger.yaml HTTP/1.1",
            response_snippet="HTTP/1.1 200 OK",
            status_code=200,
        ),
        blast_radius="single_asset",
    )

    raw = """
{
  "entry_point": "http://localhost:3000",
  "pivot_path": [
    {"step": 1, "asset": "localhost", "action": "Enumerate", "detail": "Found exposed API docs", "mitre": "T1595"}
  ],
  "reachable_sensitive_stores": [
    {"type": "database", "asset": "localhost:3306", "contents": "juice_db", "credentials_used": null}
  ],
  "blast_radius_score": 0.5,
  "blast_radius_summary": "Potential impact to backend data stores.",
  "gemini_reasoning": "Observed sensitive services.",
  "mitre_techniques": ["T1595"]
}
"""

    agent = LateralAgent.__new__(LateralAgent)
    chain = agent._parse_attack_chain(raw, finding)

    assert chain is None


def test_parse_attack_chain_accepts_string_credentials_used():
    finding = FindingDocument(
        engagement_id="eng-1",
        asset_id="asset-1",
        finding_id="finding-1",
        vulnerability_class="api",
        title="Swagger exposed",
        severity="medium",
        exploitable=True,
        affected_url="http://localhost:3000/api-docs/swagger.yaml",
        evidence=Evidence(
            request="GET /api-docs/swagger.yaml HTTP/1.1",
            response_snippet="HTTP/1.1 200 OK",
            status_code=200,
        ),
        blast_radius="single_asset",
    )

    raw = """
{
    "entry_point": "http://localhost:3000",
    "pivot_path": [
    {"step": 1, "asset": "localhost", "action": "Enumerate", "detail": "Found exposed API docs", "mitre": "T1595"}
  ],
  "reachable_sensitive_stores": [
    {"type": "database", "asset": "localhost:3306", "contents": "juice_db", "credentials_used": "unknown"}
  ],
  "blast_radius_score": 0.5,
  "blast_radius_summary": "Potential impact to backend data stores.",
  "gemini_reasoning": "Observed sensitive services.",
  "mitre_techniques": ["T1595"]
}
"""

    agent = LateralAgent.__new__(LateralAgent)
    chain = agent._parse_attack_chain(raw, finding)

    assert chain is not None
    assert chain.reachable_sensitive_stores[0].credentials_used == "unknown"

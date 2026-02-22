"""Tests for INF-03 FastAPI server (server/main.py).

Covers all five endpoints and the WebSocket:
  GET /api/health
  GET /api/findings/{eid}
  GET /api/assets/{eid}
  GET /api/chains/{eid}
  GET /api/status
  WS  /ws/live
"""

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

# MongoClient resolves DNS immediately for mongodb+srv:// URIs, which fails in
# test environments without a real connection.  Patch it before the module is
# first imported so the module-level client = MongoClient(...) is a no-op.
with patch("pymongo.MongoClient", return_value=MagicMock()):
    import server.main as server_main

client = TestClient(server_main.app)


def _mock_db(assets=None, findings=None, chains=None) -> MagicMock:
    mock = MagicMock()
    mock.assets.find.return_value = assets or []
    mock.findings.find.return_value = findings or []
    mock.attack_chains.find.return_value = chains or []
    mock.assets.count_documents.return_value = len(assets or [])
    mock.findings.count_documents.return_value = len(findings or [])
    mock.attack_chains.count_documents.return_value = len(chains or [])
    return mock


# ---------------------------------------------------------------------------
# /api/health
# ---------------------------------------------------------------------------

def test_health_returns_ok():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# /api/assets/{eid}
# ---------------------------------------------------------------------------

def test_assets_returns_list_for_engagement(monkeypatch):
    mock = _mock_db(assets=[{"engagement_id": "eng-1", "ip": "10.0.0.1", "attack_surface_score": 0.9}])
    monkeypatch.setattr(server_main, "db", mock)

    response = client.get("/api/assets/eng-1")
    assert response.status_code == 200
    payload = response.json()
    assert "assets" in payload
    assert payload["assets"][0]["ip"] == "10.0.0.1"
    mock.assets.find.assert_called_once_with({"engagement_id": "eng-1"}, {"_id": 0})


def test_assets_returns_empty_list_when_none(monkeypatch):
    monkeypatch.setattr(server_main, "db", _mock_db())

    response = client.get("/api/assets/no-such-engagement")
    assert response.status_code == 200
    assert response.json() == {"assets": []}


# ---------------------------------------------------------------------------
# /api/findings/{eid}
# ---------------------------------------------------------------------------

def test_findings_returns_list_for_engagement(monkeypatch):
    mock = _mock_db(findings=[{"engagement_id": "eng-1", "title": "SQL Injection", "severity": "high"}])
    monkeypatch.setattr(server_main, "db", mock)

    response = client.get("/api/findings/eng-1")
    assert response.status_code == 200
    payload = response.json()
    assert "findings" in payload
    assert payload["findings"][0]["title"] == "SQL Injection"
    mock.findings.find.assert_called_once_with({"engagement_id": "eng-1"}, {"_id": 0})


def test_findings_returns_empty_list_when_none(monkeypatch):
    monkeypatch.setattr(server_main, "db", _mock_db())

    response = client.get("/api/findings/no-such-engagement")
    assert response.status_code == 200
    assert response.json() == {"findings": []}


# ---------------------------------------------------------------------------
# /api/chains/{eid}
# ---------------------------------------------------------------------------

def test_chains_returns_list_for_engagement(monkeypatch):
    mock = _mock_db(chains=[{"engagement_id": "eng-1", "steps": ["recon", "exploit"]}])
    monkeypatch.setattr(server_main, "db", mock)

    response = client.get("/api/chains/eng-1")
    assert response.status_code == 200
    payload = response.json()
    assert "chains" in payload
    assert payload["chains"][0]["steps"] == ["recon", "exploit"]
    mock.attack_chains.find.assert_called_once_with({"engagement_id": "eng-1"}, {"_id": 0})


def test_chains_returns_empty_list_when_none(monkeypatch):
    monkeypatch.setattr(server_main, "db", _mock_db())

    response = client.get("/api/chains/no-such-engagement")
    assert response.status_code == 200
    assert response.json() == {"chains": []}


# ---------------------------------------------------------------------------
# /api/status
# ---------------------------------------------------------------------------

def test_status_returns_global_counts(monkeypatch):
    mock = MagicMock()
    mock.assets.count_documents.return_value = 5
    mock.findings.count_documents.return_value = 3
    mock.attack_chains.count_documents.return_value = 1
    monkeypatch.setattr(server_main, "db", mock)

    response = client.get("/api/status")
    assert response.status_code == 200
    assert response.json() == {"assets": 5, "findings": 3, "chains": 1}


def test_status_returns_zero_counts_when_empty(monkeypatch):
    monkeypatch.setattr(server_main, "db", _mock_db())

    response = client.get("/api/status")
    assert response.status_code == 200
    assert response.json() == {"assets": 0, "findings": 0, "chains": 0}


# ---------------------------------------------------------------------------
# WebSocket /ws/live
# ---------------------------------------------------------------------------

def test_websocket_accepts_connection():
    with client.websocket_connect("/ws/live"):
        pass  # connection accepted and cleanly closed — no exception expected

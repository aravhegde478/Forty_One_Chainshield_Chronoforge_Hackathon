from fastapi.testclient import TestClient

import api
import report as report_lib

client = TestClient(api.app)
ADDR = "0x" + "1" * 40

FAKE = {
    "address": ADDR, "score": 80, "rating": "High",
    "findings": [{"code": "known_malicious", "id": "Known malicious contact", "severity": "high",
                  "points": 75, "reason": "test", "evidence": ["0xabc"]}],
    "recommendations": ["Do not transact."], "transactions": [{}], "nodes": [], "edges": [],
    "meta": {"source": "live", "fetched_at": 1792700000, "truncated": False, "chain_id": 1},
}


def fake_analyze(address, chain_id=1, use_cache=True):
    return FAKE


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_invalid_address_is_rejected():
    r = client.post("/analyze", json={"address": "hello"})
    assert r.status_code == 422


def test_analyze_returns_result(monkeypatch):
    monkeypatch.setattr(api.service, "analyze_address", fake_analyze)
    r = client.post("/analyze", json={"address": ADDR})
    assert r.status_code == 200 and r.json()["rating"] == "High"


def test_provider_error_becomes_502(monkeypatch):
    def boom(*a, **k):
        raise api.blockchain.BlockchainError("provider down")
    monkeypatch.setattr(api.service, "analyze_address", boom)
    assert client.post("/analyze", json={"address": ADDR}).status_code == 502


def test_report_hash_is_stable(monkeypatch):
    monkeypatch.setattr(api.service, "analyze_address", fake_analyze)
    a = client.post("/report", json={"address": ADDR}).json()
    b = client.post("/report", json={"address": ADDR}).json()
    assert a["report_hash"] == b["report_hash"] and len(a["report_hash"]) == 64


def test_verify_accepts_original_report(monkeypatch):
    monkeypatch.setattr(api.service, "analyze_address", fake_analyze)
    data = client.post("/report", json={"address": ADDR}).json()
    r = client.post("/verify", json={"report": data["report"], "expected_hash": data["report_hash"]})
    assert r.json()["match"] is True


def test_verify_detects_tampering(monkeypatch):
    monkeypatch.setattr(api.service, "analyze_address", fake_analyze)
    data = client.post("/report", json={"address": ADDR}).json()
    tampered = {**data["report"], "score": 5, "rating": "Low"}
    r = client.post("/verify", json={"report": tampered, "expected_hash": data["report_hash"]})
    assert r.json()["match"] is False


def test_hash_ignores_formatting():
    rep = report_lib.build_report(FAKE)
    assert report_lib.hash_report(rep) == report_lib.hash_report(dict(reversed(list(rep.items()))))
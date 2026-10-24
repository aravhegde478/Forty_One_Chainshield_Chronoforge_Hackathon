import pytest

import blockchain
import database

ADDR = "0x" + "1" * 40


class FakeResp:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


def ok(result):
    return FakeResp({"status": "1", "message": "OK", "result": result})


def raw_tx(h="0xaa", value="1000000000000000000", err="0"):
    return {"hash": h, "from": "0x" + "A" * 40, "to": ADDR, "value": value,
            "timeStamp": "1792700000", "isError": err}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setenv("ETHERSCAN_API_KEY", "test")
    monkeypatch.setattr(blockchain, "REQUEST_GAP", 0)
    monkeypatch.setattr(blockchain.time, "sleep", lambda s: None)


def test_invalid_address_rejected():
    with pytest.raises(blockchain.InvalidAddress):
        blockchain.fetch_transactions("not-an-address")


def test_normalizes_values_and_failed_transactions(monkeypatch):
    monkeypatch.setattr(blockchain.requests, "get",
                        lambda *a, **k: ok([raw_tx(), raw_tx("0xbb", err="1")]))
    r = blockchain.fetch_transactions(ADDR)
    assert r["source"] == "live"
    assert r["transactions"][0]["value"] == 1.0
    assert r["transactions"][0]["from"] == "0x" + "a" * 40
    assert r["transactions"][1]["value"] == 0.0


def test_second_call_uses_cache(monkeypatch):
    calls = []

    def fake_get(*a, **k):
        calls.append(1)
        return ok([raw_tx()])

    monkeypatch.setattr(blockchain.requests, "get", fake_get)
    blockchain.fetch_transactions(ADDR)
    r = blockchain.fetch_transactions(ADDR)
    assert r["source"] == "cache" and len(calls) == 1


def test_no_transactions_returns_empty_list(monkeypatch):
    monkeypatch.setattr(blockchain.requests, "get", lambda *a, **k: FakeResp(
        {"status": "0", "message": "No transactions found", "result": []}))
    assert blockchain.fetch_transactions(ADDR)["transactions"] == []


def test_falls_back_to_stale_cache_when_api_fails(monkeypatch):
    monkeypatch.setattr(blockchain.requests, "get", lambda *a, **k: ok([raw_tx()]))
    blockchain.fetch_transactions(ADDR)
    monkeypatch.setattr(blockchain.requests, "get", lambda *a, **k: FakeResp(
        {"status": "0", "message": "NOTOK", "result": "Invalid API Key"}))
    r = blockchain.fetch_transactions(ADDR, use_cache=False)
    assert r["source"] == "stale-cache" and len(r["transactions"]) == 1
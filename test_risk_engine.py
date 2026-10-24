import config
from risk_engine import analyze, load_indicators

IND = load_indicators()
BAD = next(a for a, r in IND.items() if r["category"] == "malicious")
MIXER = next(a for a, r in IND.items() if r["category"] == "mixer")
SANCTIONED = next(a for a, r in IND.items() if r["category"] == "sanctioned")

ME = "0x" + "1" * 40
FRIEND = "0x" + "2" * 40
BASE = 1_792_700_000


def tx(h, frm, to, value=1.0, ts=BASE):
    return {"hash": h, "from": frm, "to": to, "value": value, "timestamp": ts}


def codes(result):
    return {f["code"] for f in result["findings"]}


def test_no_transactions_is_insufficient():
    r = analyze(ME, [], IND)
    assert r["rating"] == "Insufficient data" and r["score"] == 0


def test_clean_wallet_is_low():
    r = analyze(ME, [tx("0x1", ME, FRIEND)], IND)
    assert r["rating"] == "Low" and r["score"] == 0 and r["findings"] == []


def test_malicious_contact_is_high_with_evidence():
    r = analyze(ME, [tx("0x2", BAD, ME)], IND)
    assert r["rating"] == "High"
    assert r["findings"][0]["evidence"] == ["0x2"]


def test_sanctioned_contact_is_high():
    assert analyze(ME, [tx("0x3", ME, SANCTIONED)], IND)["rating"] == "High"


def test_mixer_alone_is_medium():
    r = analyze(ME, [tx("0x4", ME, MIXER)], IND)
    assert r["rating"] == "Medium" and codes(r) == {"mixer_exposure"}


def test_rapid_pass_through_detected():
    r = analyze(ME, [tx("0xin", FRIEND, ME, 5.0, BASE), tx("0xout", ME, "0x" + "3" * 40, 4.9, BASE + 240)], IND)
    assert "rapid_pass_through" in codes(r)
    assert set(r["findings"][0]["evidence"]) == {"0xin", "0xout"}


def test_slow_forwarding_not_flagged():
    r = analyze(ME, [tx("0xin", FRIEND, ME, 5.0, BASE),
                     tx("0xout", ME, "0x" + "3" * 40, 4.9, BASE + 2 * 86400)], IND)
    assert "rapid_pass_through" not in codes(r)


def test_new_wallet_burst_detected():
    burst = [tx(f"0xb{i}", FRIEND, ME, 0.1, BASE + i * 60) for i in range(12)]
    assert "new_wallet_burst" in codes(analyze(ME, burst, IND))


def test_old_wallet_with_same_burst_not_flagged():
    burst = [tx(f"0xb{i}", FRIEND, ME, 0.1, BASE + i * 60) for i in range(12)]
    burst.append(tx("0xlate", FRIEND, ME, 0.1, BASE + 30 * 86400))
    assert "new_wallet_burst" not in codes(analyze(ME, burst, IND))


def test_score_is_capped_at_100():
    r = analyze(ME, [tx("0xa", BAD, ME), tx("0xb", ME, SANCTIONED)], IND)
    assert r["score"] == 100


def test_address_case_is_ignored():
    r = analyze(ME.upper().replace("0X", "0x"), [tx("0x5", BAD.upper().replace("0X", "0x"), ME)], IND)
    assert r["rating"] == "High"


def test_graph_marks_flagged_nodes():
    r = analyze(ME, [tx("0x6", BAD, ME), tx("0x7", ME, FRIEND)], IND)
    types = {n["label"]: n["type"] for n in r["nodes"]}
    assert "malicious" in types.values() and "normal" in types.values()


def test_transaction_rows_show_flags():
    r = analyze(ME, [tx("0x8", BAD, ME)], IND)
    assert r["transactions"][0]["Flag"] == "Malicious"

def test_listed_target_is_flagged():
    r = analyze(BAD, [tx("0x9", FRIEND, BAD)], IND)
    assert "target_listed" in codes(r) and r["rating"] == "High"


def test_listed_mixer_target_is_high():
    r = analyze(MIXER, [tx("0xa", FRIEND, MIXER)], IND)
    assert "target_listed" in codes(r) and r["rating"] == "High"


def test_reason_includes_label():
    r = analyze(ME, [tx("0xb", BAD, ME)], IND)
    assert IND[BAD]["label"] in r["findings"][0]["reason"]

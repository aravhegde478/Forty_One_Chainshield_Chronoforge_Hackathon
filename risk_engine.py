import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import config

THREAT_FILE = Path(__file__).parent / "data" / "threat_indicators.csv"


# ---------- helpers ----------
def load_indicators(path=THREAT_FILE) -> dict:
    """Return {address: row} with lowercase addresses."""
    indicators = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            indicators[row["address"].strip().lower()] = row
    return indicators


def short(value: str) -> str:
    return value if len(value) <= 14 else f"{value[:6]}...{value[-4:]}"


def _normalize(transactions: list) -> list:
    """Lowercase addresses, coerce types, sort oldest to newest."""
    out = []
    for t in transactions:
        out.append({
            "hash": t["hash"],
            "from": (t.get("from") or "").lower(),
            "to": (t.get("to") or "").lower(),   # contract creations have no "to"
            "value": float(t.get("value", 0)),
            "timestamp": int(t["timestamp"]),
        })
    return sorted(out, key=lambda t: t["timestamp"])


def _counterparty(address: str, tx: dict) -> str:
    return tx["to"] if tx["from"] == address else tx["from"]


def _fmt_delay(seconds: int) -> str:
    return f"{seconds} seconds" if seconds < 60 else f"{round(seconds / 60)} minutes"


def _finding(code: str, reason: str, evidence: list, points: int = None) -> dict:
    return {
        "code": code,
        "id": config.TITLES[code],            # display title used by the dashboard
        "severity": config.SEVERITY[code],
        "points": points if points is not None else config.WEIGHTS[code],
        "reason": reason,
        "evidence": list(dict.fromkeys(evidence))[: config.MAX_EVIDENCE],
    }


# ---------- detectors ----------
def detect_target_listed(address, indicators):
    """The analyzed address is itself on a threat list."""
    ind = indicators.get(address)
    if not ind:
        return None
    category = ind["category"]
    points = config.TARGET_LISTED_POINTS.get(category)
    if points is None:
        return None
    nouns = {"sanctioned": "a sanctioned address", "malicious": "a known malicious address",
             "mixer": "a known mixing service"}
    label = ind.get("label") or category
    source = ind.get("source") or "threat list"
    reason = f"This address is itself listed as {nouns[category]} ({label}; source: {source})."
    return _finding("target_listed", reason, [f"listed by {source}"], points)


def detect_indicator_contacts(address, txs, indicators) -> list:
    """Direct transfers with sanctioned, malicious or mixer addresses."""
    hits = {"sanctioned": [], "malicious": [], "mixer": []}
    for tx in txs:
        cp = _counterparty(address, tx)
        ind = indicators.get(cp)
        if ind and ind["category"] in hits:
            hits[ind["category"]].append((tx["hash"], cp))

    def build(category, code, noun):
        if not hits[category]:
            return None
        n_tx = len(hits[category])
        n_cp = len({cp for _, cp in hits[category]})
        labels = sorted({indicators[cp].get("label") for _, cp in hits[category]
                         if indicators[cp].get("label")})
        label_text = f" ({'; '.join(labels[:3])})" if labels else ""
        reason = f"{n_tx} transaction(s) with {n_cp} {noun}{label_text}."
        return _finding(code, reason, [h for h, _ in hits[category]])

    results = [
        build("sanctioned", "sanctioned", "sanctioned address(es)"),
        build("malicious", "known_malicious", "address(es) flagged as malicious"),
        build("mixer", "mixer_exposure", "mixing service address(es)"),
    ]
    return [r for r in results if r]


def detect_pass_through(address, txs):
    """Funds received and forwarded again within a short window."""
    incoming = [t for t in txs if t["to"] == address and t["from"] != address and t["value"] > 0]
    outgoing = [t for t in txs if t["from"] == address and t["to"] != address]
    used, evidence, fastest, pairs = set(), [], None, 0

    for i in incoming:
        for o in outgoing:
            if o["hash"] in used:
                continue
            delay = o["timestamp"] - i["timestamp"]
            if 0 <= delay <= config.PASS_THROUGH_WINDOW_SEC and \
                    o["value"] >= i["value"] * config.PASS_THROUGH_MIN_RATIO:
                used.add(o["hash"])
                evidence += [i["hash"], o["hash"]]
                pairs += 1
                fastest = delay if fastest is None else min(fastest, delay)
                break

    if not pairs:
        return None
    reason = (f"{pairs} incoming transfer(s) were forwarded within "
              f"{_fmt_delay(config.PASS_THROUGH_WINDOW_SEC)}; "
              f"the fastest took {_fmt_delay(fastest)}.")
    return _finding("rapid_pass_through", reason, evidence)


def detect_new_wallet_burst(txs):
    """Many transactions right after a wallet first appears.
    Only reliable if the full history was fetched, not a truncated slice."""
    first, last = txs[0]["timestamp"], txs[-1]["timestamp"]
    if last - first > config.NEW_WALLET_MAX_AGE_SEC:
        return None
    window = [t for t in txs if t["timestamp"] - first <= config.BURST_WINDOW_SEC]
    if len(window) < config.BURST_MIN_TX:
        return None
    reason = (f"{len(window)} transactions within "
              f"{round(config.BURST_WINDOW_SEC / 3600)} hours of the wallet's first activity.")
    return _finding("new_wallet_burst", reason, [t["hash"] for t in window])


# ---------- output builders ----------
def _recommendations(rating: str, codes: set) -> list:
    if rating == "Insufficient data":
        return ["Not enough on-chain activity to assess this address. Treat it as unverified."]
    recs = []
    if rating == "High":
        recs += ["Do not send funds or sign approvals involving this address.",
                 "If you already interacted with it, revoke token approvals and consider moving funds to a new wallet."]
    elif rating == "Medium":
        recs += ["Proceed with caution and verify who controls this address before large transfers."]
    if "target_listed" in codes:
        recs.append("This address itself appears on a threat list. Do not send it funds.")
    if "sanctioned" in codes:
        recs.append("Dealing with sanctioned addresses can carry legal and compliance risk.")
    if "mixer_exposure" in codes:
        recs.append("Check whether the mixer contact was a one-off or a repeated pattern.")
    if "rapid_pass_through" in codes:
        recs.append("Fast forwarding of funds is a common laundering pattern; verify the counterparties.")
    if not recs:
        recs.append("No risk indicators found. Always double-check addresses before signing.")
    return recs


def _build_graph(address, txs, indicators):
    def node_type(a):
        cat = indicators.get(a, {}).get("category")
        return "malicious" if cat in ("malicious", "sanctioned") else "mixer" if cat == "mixer" else "normal"

    counts = Counter(_counterparty(address, t) for t in txs)
    counts.pop(address, None)
    ranked = sorted(counts, key=lambda a: (node_type(a) == "normal", -counts[a]))
    ranked = ranked[: config.MAX_GRAPH_NODES - 1]

    nodes = [{"id": "target", "label": short(address), "type": "target"}]
    nodes += [{"id": a, "label": short(a), "type": node_type(a)} for a in ranked]

    edges, seen = [], set()
    for t in txs:
        cp = _counterparty(address, t)
        if cp not in ranked:
            continue
        edge = (cp, "target") if t["to"] == address else ("target", cp)
        if edge not in seen:
            seen.add(edge)
            edges.append(edge)
    return nodes, edges


def _tx_rows(address, txs, findings):
    flag_for = {}
    for f in sorted(findings, key=lambda f: -f["points"]):   # strongest flag wins
        for h in f["evidence"]:
            flag_for.setdefault(h, config.FLAG_LABELS[f["code"]])
    rows = []
    for t in sorted(txs, key=lambda t: -t["timestamp"]):
        when = datetime.fromtimestamp(t["timestamp"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
        rows.append({"Time": when, "Hash": short(t["hash"]), "From": short(t["from"]),
                     "To": short(t["to"]) if t["to"] else "(contract creation)",
                     "Value (ETH)": round(t["value"], 4), "Flag": flag_for.get(t["hash"], "-")})
    return rows


# ---------- main entry point ----------
def analyze(address: str, transactions: list, indicators: dict = None) -> dict:
    address = address.strip().lower()
    indicators = indicators if indicators is not None else load_indicators()

    if len(transactions) < config.MIN_TX_REQUIRED:
        return {"address": address, "score": 0, "rating": "Insufficient data", "findings": [],
                "recommendations": _recommendations("Insufficient data", set()),
                "transactions": [], "nodes": [{"id": "target", "label": short(address), "type": "target"}],
                "edges": []}

    txs = _normalize(transactions)

    findings = []
    listed = detect_target_listed(address, indicators)
    if listed:
        findings.append(listed)
    findings += detect_indicator_contacts(address, txs, indicators)
    for finding in (detect_pass_through(address, txs), detect_new_wallet_burst(txs)):
        if finding:
            findings.append(finding)
    findings.sort(key=lambda f: -f["points"])

    score = min(100, sum(f["points"] for f in findings))
    rating = config.rating_for(score)
    nodes, edges = _build_graph(address, txs, indicators)

    return {
        "address": address,
        "score": score,
        "rating": rating,
        "findings": findings,
        "recommendations": _recommendations(rating, {f["code"] for f in findings}),
        "transactions": _tx_rows(address, txs, findings),
        "nodes": nodes,
        "edges": edges,
    }


if __name__ == "__main__":
    # quick manual demo: python risk_engine.py
    ind = load_indicators()
    bad = next(a for a, r in ind.items() if r["category"] == "malicious")
    mixer = next(a for a, r in ind.items() if r["category"] == "mixer")
    me, friend, base = "0x" + "7a" * 20, "0x" + "41" * 20, 1_792_700_000
    sample = [
        {"hash": "0xin1", "from": bad, "to": me, "value": 5.0, "timestamp": base},
        {"hash": "0xout1", "from": me, "to": friend, "value": 4.9, "timestamp": base + 240},
        {"hash": "0xmix1", "from": me, "to": mixer, "value": 1.0, "timestamp": base + 900},
    ]
    print(json.dumps(analyze(me, sample), indent=2))
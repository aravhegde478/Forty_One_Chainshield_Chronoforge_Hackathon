import csv
import re
from collections import Counter
from pathlib import Path

DATA = Path(__file__).parent / "data"
RAW = DATA / "raw"
OUT = DATA / "threat_indicators.csv"
ADDR_RE = re.compile(r"^0x[0-9a-f]{40}$")
RANK = {"mixer": 1, "malicious": 2, "sanctioned": 3}   # on duplicates, the more severe one wins


def clean(value):
    a = (value or "").strip().lower()
    return a if ADDR_RE.match(a) else None


def read_rows(path):
    if not path.exists():
        print(f"  skipped (not found): {path}")
        return []
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def read_lines(path):
    if not path.exists():
        print(f"  skipped (not found): {path}")
        return []
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    return [l.strip() for l in lines if l.strip() and not l.startswith("#")]


def build():
    found, skipped = {}, 0

    def add(address, category, label, source):
        nonlocal skipped
        a = clean(address)
        if not a or category not in RANK:
            skipped += 1
            return
        old = found.get(a)
        if old is None or RANK[category] > RANK[old["category"]]:
            found[a] = {"address": a, "category": category, "label": label, "source": source}

    for r in read_rows(DATA / "demo_indicators.csv"):
        add(r.get("address"), (r.get("category") or "").strip(), r.get("label", ""), "synthetic")
    for r in read_rows(RAW / "mixers.csv"):
        add(r.get("address"), "mixer", r.get("label", "Mixing service"), r.get("source", "manual"))
    for r in read_rows(RAW / "malicious.csv"):
        add(r.get("address"), "malicious", r.get("label", "Flagged address"), r.get("source", "manual"))
    for line in read_lines(RAW / "sanctioned_addresses_ETH.txt"):
        add(line, "sanctioned", "OFAC sanctioned address", "OFAC SDN")

    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["address", "category", "label", "source"])
        w.writeheader()
        w.writerows(found.values())

    counts = Counter(r["category"] for r in found.values())
    print(f"Wrote {len(found)} indicators to {OUT}")
    for cat in ("sanctioned", "malicious", "mixer"):
        print(f"  {cat:<11} {counts.get(cat, 0)}")
    if skipped:
        print(f"  skipped {skipped} invalid rows")


if __name__ == "__main__":
    build()
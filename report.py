import hashlib
import json

REPORT_VERSION = 1


def build_report(result: dict) -> dict:
    """Turn an analysis result into the report that gets hashed.
    Uses the data-fetch time (not 'now'), so the same data always gives the same hash."""
    meta = result.get("meta") or {}
    return {
        "report_version": REPORT_VERSION,
        "address": result["address"],
        "chain_id": meta.get("chain_id"),
        "data_fetched_at": meta.get("fetched_at"),
        "data_truncated": meta.get("truncated"),
        "transactions_analyzed": len(result.get("transactions", [])),
        "score": result["score"],
        "rating": result["rating"],
        "findings": result["findings"],
        "recommendations": result["recommendations"],
    }


def canonical_json(report: dict) -> str:
    """One fixed text form, so formatting differences can never change the hash."""
    return json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_report(report: dict) -> str:
    return hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()


def verify_report(report: dict, expected_hash: str) -> dict:
    computed = hash_report(report)
    expected = expected_hash.strip().lower().removeprefix("0x")
    return {"match": computed == expected, "computed_hash": computed, "expected_hash": expected}
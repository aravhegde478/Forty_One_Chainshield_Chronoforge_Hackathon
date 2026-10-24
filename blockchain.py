import os
import re
import time

import requests
from dotenv import load_dotenv

import database

load_dotenv()

API_URL = "https://api.etherscan.io/v2/api"
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
PAGE_SIZE = 1000          # free-tier maximum per request
CACHE_MAX_AGE = 3600      # seconds before a cached lookup is refreshed
REQUEST_GAP = 0.4         # pause after each live call, stays under the rate limit
RETRIES = 3


class BlockchainError(Exception):
    pass


class InvalidAddress(BlockchainError):
    pass


def is_valid_address(address: str) -> bool:
    return bool(ADDRESS_RE.match(address.strip()))


def _normalize(raw: list) -> list:
    """Convert explorer rows into the format the engine expects."""
    out = []
    for t in raw:
        failed = t.get("isError") == "1"
        out.append({
            "hash": t["hash"],
            "from": (t.get("from") or "").lower(),
            "to": (t.get("to") or "").lower(),               # empty for contract creation
            "value": 0.0 if failed else int(t["value"]) / 1e18,   # wei -> ETH
            "timestamp": int(t["timeStamp"]),
        })
    return out


def _call_api(params: dict):
    key = os.getenv("ETHERSCAN_API_KEY")
    if not key:
        raise BlockchainError("ETHERSCAN_API_KEY is missing. Add it to your .env file.")
    params = {**params, "apikey": key}
    last_error = "unknown error"

    for attempt in range(RETRIES):
        try:
            resp = requests.get(API_URL, params=params, timeout=15)
            resp.raise_for_status()
            body = resp.json()
        except (requests.RequestException, ValueError) as e:
            last_error = f"network error: {e}"
            time.sleep(1 + attempt)
            continue

        if body.get("status") == "1":
            return body["result"]

        message = str(body.get("message", ""))
        if "no transactions found" in message.lower():
            return []
        text = f"{message} {body.get('result', '')}".strip()
        if "rate limit" in text.lower():
            last_error = text
            time.sleep(1.5 * (attempt + 1))
            continue
        raise BlockchainError(text)

    raise BlockchainError(last_error)


def _package(txs: list, source: str, fetched_at: int) -> dict:
    return {"transactions": txs, "source": source, "fetched_at": fetched_at,
            "truncated": len(txs) >= PAGE_SIZE}


def fetch_transactions(address: str, chain_id: int = 1, use_cache: bool = True,
                       max_age: int = CACHE_MAX_AGE) -> dict:
    """Return {transactions, source, fetched_at, truncated}.
    source is 'live', 'cache', or 'stale-cache' (API failed, older data used)."""
    address = address.strip().lower()
    if not is_valid_address(address):
        raise InvalidAddress("That is not a valid Ethereum address (0x followed by 40 hex characters).")

    database.init_db()
    cached = database.get_cached(address, chain_id)
    now = int(time.time())

    if use_cache and cached and now - cached[0] <= max_age:
        return _package(cached[1], "cache", cached[0])

    try:
        raw = _call_api({
            "chainid": chain_id, "module": "account", "action": "txlist",
            "address": address, "startblock": 0, "endblock": 99999999,
            "page": 1, "offset": PAGE_SIZE, "sort": "desc",   # newest first
        })
        time.sleep(REQUEST_GAP)
    except BlockchainError:
        if cached:                                   # demo-safe fallback
            return _package(cached[1], "stale-cache", cached[0])
        raise

    txs = _normalize(raw)
    database.save_cache(address, chain_id, now, txs)
    return _package(txs, "live", now)
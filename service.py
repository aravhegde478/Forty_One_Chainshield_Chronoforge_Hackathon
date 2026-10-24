import blockchain
import database
import risk_engine


def analyze_address(address: str, chain_id: int = 1, use_cache: bool = True) -> dict:
    fetched = blockchain.fetch_transactions(address, chain_id, use_cache)
    indicators = database.load_indicators()
    result = risk_engine.analyze(address, fetched["transactions"], indicators)
    result["meta"] = {"source": fetched["source"], "fetched_at": fetched["fetched_at"],
                      "truncated": fetched["truncated"], "chain_id": chain_id}
    return result


if __name__ == "__main__":
    import sys
    r = analyze_address(sys.argv[1])
    print(f"{r['address']}\nscore {r['score']} ({r['rating']}) | source: {r['meta']['source']}"
          f" | transactions: {len(r['transactions'])} | truncated: {r['meta']['truncated']}")
    for f in r["findings"]:
        print(f"  +{f['points']:>3}  {f['id']}: {f['reason']}")
import os
from typing import Optional

from dotenv import load_dotenv
from web3 import Web3

load_dotenv()

# Only these test networks are accepted. A mainnet RPC can never be used by mistake.
ALLOWED_TESTNETS = {11155111: "Sepolia", 560048: "Hoodi"}
DEFAULT_EXPLORERS = {11155111: "https://sepolia.etherscan.io"}

ABI = [
    {"inputs": [{"internalType": "bytes32", "name": "reportHash", "type": "bytes32"}],
     "name": "anchor", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "reportHash", "type": "bytes32"}],
     "name": "getAnchor",
     "outputs": [{"internalType": "address", "name": "anchoredBy", "type": "address"},
                 {"internalType": "uint64", "name": "timestamp", "type": "uint64"}],
     "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "bytes32", "name": "reportHash", "type": "bytes32"}],
     "name": "isAnchored", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
     "stateMutability": "view", "type": "function"},
]


class ChainError(Exception):
    pass


def _settings() -> dict:
    try:
        chain_id = int(os.getenv("CHAIN_ID", "11155111"))
    except ValueError:
        chain_id = 0
    key = (os.getenv("TESTNET_PRIVATE_KEY") or "").strip()
    if key and not key.startswith("0x"):
        key = "0x" + key
    explorer = (os.getenv("EXPLORER_URL") or DEFAULT_EXPLORERS.get(chain_id, "")).rstrip("/")
    return {
        "rpc": (os.getenv("TESTNET_RPC_URL") or "").strip(),
        "key": key,
        "registry": (os.getenv("REGISTRY_ADDRESS") or "").strip(),
        "chain_id": chain_id,
        "name": ALLOWED_TESTNETS.get(chain_id, f"chain {chain_id}"),
        "explorer": explorer,
    }


def status() -> dict:
    """Local check only (no network calls). Never includes the private key."""
    s = _settings()
    return {"network": s["name"], "chain_id": s["chain_id"], "registry": s["registry"],
            "explorer": s["explorer"],
            "can_verify": bool(s["rpc"] and s["registry"]),
            "can_anchor": bool(s["rpc"] and s["registry"] and s["key"])}


def _to_bytes32(report_hash: str) -> bytes:
    h = (report_hash or "").strip().lower().removeprefix("0x")
    if len(h) != 64:
        raise ChainError("A report hash must be 64 hexadecimal characters.")
    try:
        return bytes.fromhex(h)
    except ValueError:
        raise ChainError("A report hash must be 64 hexadecimal characters.")


def _connect(s: dict):
    if s["chain_id"] not in ALLOWED_TESTNETS:
        raise ChainError(f"Chain ID {s['chain_id']} is not an allowed test network. "
                         "Set CHAIN_ID to a test network in .env.")
    if not s["rpc"] or not s["registry"]:
        raise ChainError("Blockchain settings are missing. Set TESTNET_RPC_URL and "
                         "REGISTRY_ADDRESS in .env.")
    w3 = Web3(Web3.HTTPProvider(s["rpc"], request_kwargs={"timeout": 20}))
    try:
        if not w3.is_connected():
            raise ChainError("Cannot reach the blockchain RPC endpoint.")
        actual = w3.eth.chain_id
    except ChainError:
        raise
    except Exception as e:
        raise ChainError(f"Cannot reach the blockchain RPC endpoint: {e}")
    if actual != s["chain_id"]:
        raise ChainError(f"The RPC endpoint reports chain ID {actual}, expected {s['chain_id']}. "
                         "Refusing to continue.")
    try:
        address = Web3.to_checksum_address(s["registry"])
    except ValueError:
        raise ChainError("REGISTRY_ADDRESS in .env is not a valid address.")
    if not w3.eth.get_code(address):
        raise ChainError("No contract found at REGISTRY_ADDRESS on this network.")
    return w3, w3.eth.contract(address=address, abi=ABI)


def get_anchor(report_hash: str) -> Optional[dict]:
    """Return the on-chain record for this hash, or None if it was never anchored."""
    s = _settings()
    b = _to_bytes32(report_hash)
    w3, contract = _connect(s)
    try:
        anchored_by, timestamp = contract.functions.getAnchor(b).call()
    except Exception as e:
        raise ChainError(f"On-chain lookup failed: {e}")
    if timestamp == 0:
        return None
    return {"anchored_by": anchored_by, "timestamp": int(timestamp), "network": s["name"]}


def anchor_hash(report_hash: str) -> dict:
    s = _settings()
    if not s["key"]:
        raise ChainError("TESTNET_PRIVATE_KEY is missing in .env, so anchoring is disabled.")
    b = _to_bytes32(report_hash)
    w3, contract = _connect(s)

    try:
        anchored_by, timestamp = contract.functions.getAnchor(b).call()
    except Exception as e:
        raise ChainError(f"On-chain lookup failed: {e}")
    if timestamp != 0:
        return {"status": "already_anchored", "tx_hash": None, "explorer_url": None,
                "timestamp": int(timestamp), "anchored_by": anchored_by, "network": s["name"]}

    account = w3.eth.account.from_key(s["key"])
    if w3.eth.get_balance(account.address) == 0:
        raise ChainError(f"The anchoring wallet ({account.address}) has no test ETH. Use a faucet.")

    try:
        tx = contract.functions.anchor(b).build_transaction({
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "chainId": s["chain_id"],
        })
        signed = w3.eth.account.sign_transaction(tx, s["key"])
        raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
        tx_hash = w3.eth.send_raw_transaction(raw)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    except Exception as e:
        raise ChainError(f"Anchoring failed: {e}")
    if receipt.status != 1:
        raise ChainError("The anchoring transaction was reverted.")

    block = w3.eth.get_block(receipt.blockNumber)
    h = "0x" + tx_hash.hex().removeprefix("0x")
    return {"status": "anchored", "tx_hash": h,
            "explorer_url": f"{s['explorer']}/tx/{h}" if s["explorer"] else None,
            "timestamp": int(block.timestamp), "anchored_by": account.address,
            "network": s["name"]}
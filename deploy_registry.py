import sys
from pathlib import Path

import solcx
from web3 import Web3

import chain

SOURCE = Path(__file__).parent / "contracts" / "ReportRegistry.sol"
SOLC_VERSION = "0.8.20"


def main():
    s = chain._settings()
    if s["chain_id"] not in chain.ALLOWED_TESTNETS:
        sys.exit("CHAIN_ID is not an allowed test network.")
    if not s["rpc"] or not s["key"]:
        sys.exit("Set TESTNET_RPC_URL and TESTNET_PRIVATE_KEY in .env first.")

    w3 = Web3(Web3.HTTPProvider(s["rpc"], request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        sys.exit("Cannot reach the RPC endpoint.")
    if w3.eth.chain_id != s["chain_id"]:
        sys.exit(f"RPC chain ID is {w3.eth.chain_id}, expected {s['chain_id']}. Refusing to continue.")

    account = w3.eth.account.from_key(s["key"])
    balance = w3.eth.get_balance(account.address)
    print(f"Network: {s['name']} (chain {s['chain_id']})")
    print(f"Wallet:  {account.address}")
    print(f"Balance: {w3.from_wei(balance, 'ether')} test ETH")
    if balance == 0:
        sys.exit("This wallet has no test ETH. Use a faucet, then run this again.")

    print("Compiling (the first run downloads the Solidity compiler)...")
    solcx.install_solc(SOLC_VERSION)
    compiled = solcx.compile_source(SOURCE.read_text(encoding="utf-8"),
                                    output_values=["abi", "bin"], solc_version=SOLC_VERSION)
    _, iface = compiled.popitem()
    contract = w3.eth.contract(abi=iface["abi"], bytecode=iface["bin"])

    tx = contract.constructor().build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "chainId": s["chain_id"],
    })
    signed = w3.eth.account.sign_transaction(tx, s["key"])
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    tx_hash = w3.eth.send_raw_transaction(raw)
    print("Deploying... waiting for confirmation")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    if receipt.status != 1:
        sys.exit("Deployment failed.")
    print("\nDeployed! Add this line to your .env:")
    print(f"REGISTRY_ADDRESS={receipt.contractAddress}")


if __name__ == "__main__":
    main()
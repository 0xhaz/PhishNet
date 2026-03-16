"""Ethereum data fetching via Alchemy/QuickNode (web3.py) and Etherscan API."""
from __future__ import annotations

import os
import httpx
from web3 import Web3

ALCHEMY_URL = os.getenv("ALCHEMY_RPC_URL", "")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
ETHERSCAN_BASE = "https://api.etherscan.io/v2/api"

w3 = Web3(Web3.HTTPProvider(ALCHEMY_URL)) if ALCHEMY_URL else None


class EthDataFetcher:
    def __init__(self):
        self._client = httpx.Client(timeout=30)

    # --- web3 methods ---

    def get_contract_bytecode(self, address: str) -> bytes:
        assert w3, "ALCHEMY_RPC_URL not set"
        return bytes(w3.eth.get_code(Web3.to_checksum_address(address)))

    def get_block_timestamp(self, block_number: int) -> int:
        assert w3
        block = w3.eth.get_block(block_number)
        return block["timestamp"]

    # --- Etherscan methods ---

    def _etherscan(self, params: dict) -> dict:
        params["apikey"] = ETHERSCAN_API_KEY
        params.setdefault("chainid", "1")
        resp = self._client.get(ETHERSCAN_BASE, params=params)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "1":
            raise ValueError(f"Etherscan error: {data.get('message')}")
        return data["result"]

    def get_contract_creation_tx(self, address: str) -> dict:
        result = self._etherscan({
            "module": "contract",
            "action": "getcontractcreation",
            "contractaddresses": address,
        })
        return result[0] if result else {}

    def get_token_transfers(self, address: str) -> list[dict]:
        return self._etherscan({
            "module": "account",
            "action": "tokentx",
            "address": address,
            "sort": "asc",
        })

    def get_internal_transactions(self, tx_hash: str) -> list[dict]:
        return self._etherscan({
            "module": "account",
            "action": "txlistinternal",
            "txhash": tx_hash,
        })

    def get_transaction_trace(self, tx_hash: str) -> dict:
        assert w3
        return w3.manager.request_blocking(
            "debug_traceTransaction", [tx_hash, {"tracer": "callTracer"}]
        )

    def get_erc20_balances(self, address: str) -> list[dict]:
        return self._etherscan({
            "module": "account",
            "action": "tokenlist",
            "address": address,
        })

    def get_contract_deployer(self, address: str) -> str | None:
        """Get the deployer of a contract. Tries Etherscan first, falls back to Alchemy."""
        # Try Etherscan
        try:
            result = self.get_contract_creation_tx(address)
            if result and result.get("contractCreator"):
                return result["contractCreator"].lower()
        except Exception:
            pass

        # Fallback: Alchemy alchemy_getAssetTransfers for internal txs TO the address
        if not ALCHEMY_URL:
            return None
        try:
            resp = self._client.post(ALCHEMY_URL, json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "alchemy_getAssetTransfers",
                "params": [{
                    "toAddress": address,
                    "category": ["internal"],
                    "maxCount": "0x1",
                    "order": "asc",
                }],
            })
            data = resp.json()
            transfers = data.get("result", {}).get("transfers", [])
            if transfers:
                return transfers[0].get("from", "").lower()
        except Exception:
            pass

        return None

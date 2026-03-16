"""Module 2 — Pool-based phishing detector (covers ~3/104 known attacks)."""
from __future__ import annotations
from dataclasses import dataclass, field

from core.bytecode_analyzer import BytecodeAnalyzer, DANGEROUS_SELECTORS
from core.data_fetcher import EthDataFetcher, w3
from detectors.token_detector import TokenPhishingDetector

fetcher = EthDataFetcher()
token_detector = TokenPhishingDetector()

# Function selectors for Uniswap V2 pair methods
TOKEN0_SELECTOR = "0dfe1681"  # token0()
TOKEN1_SELECTOR = "d21220a7"  # token1()
GET_RESERVES_SELECTOR = "0902f1ac"  # getReserves()

# Well-known tokens (not suspicious)
KNOWN_TOKENS = {
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # WETH
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC
    "0xdac17f958d2ee523a2206206994597c13d831ec7",  # USDT
    "0x6b175474e89094c44da98b954eedeac495271d0f",  # DAI
}


@dataclass
class PoolRiskReport:
    address: str
    risk_score: int
    attack_type: str = "pool"
    detection_signals: list[str] = field(default_factory=list)
    token0: str = ""
    token1: str = ""


class PoolPhishingDetector:
    def analyze_pool(self, pool_address: str) -> PoolRiskReport:
        signals: list[str] = []
        score = 0

        # First check if it even looks like a pool (has token0/token1 selectors)
        try:
            bytecode = fetcher.get_contract_bytecode(pool_address)
        except Exception:
            return PoolRiskReport(address=pool_address, risk_score=0,
                                  detection_signals=["Could not fetch bytecode"])

        if not bytecode or len(bytecode) < 10:
            return PoolRiskReport(address=pool_address, risk_score=0)

        hex_code = bytecode.hex()
        has_pool_interface = TOKEN0_SELECTOR in hex_code and TOKEN1_SELECTOR in hex_code
        if not has_pool_interface:
            return PoolRiskReport(address=pool_address, risk_score=0,
                                  detection_signals=["Not a DEX pool (no token0/token1)"])

        signals.append("DEX pool interface detected")

        # Get pool tokens via web3 call
        token0, token1 = self._get_pool_tokens(pool_address)

        # Signal 1: check if either token is fresh and suspicious
        for label, token in [("token0", token0), ("token1", token1)]:
            if not token or token.lower() in KNOWN_TOKENS:
                continue
            try:
                creation = fetcher.get_contract_creation_tx(token)
                if creation:
                    # Check token bytecode for malicious patterns
                    token_report = token_detector.analyze_contract(token)
                    if token_report.risk_score >= 40:
                        score += 40
                        signals.append(f"Suspicious {label}: {token[:10]}... (risk={token_report.risk_score})")
                        signals.extend([f"  - {s}" for s in token_report.detection_signals[:3]])
            except Exception:
                pass

        # Signal 2: pool bytecode has dangerous selectors (callback exploit)
        analyzer = BytecodeAnalyzer(bytecode)
        selectors = analyzer.extract_four_byte_selectors()
        dangerous = selectors & set(DANGEROUS_SELECTORS.keys())
        if dangerous:
            score += 30
            names = [DANGEROUS_SELECTORS[s] for s in dangerous]
            signals.append(f"Pool contains dangerous selectors: {', '.join(names)}")

        # Signal 3: tx.origin in pool bytecode (very suspicious for a pool)
        if analyzer.check_tx_origin_usage():
            score += 35
            signals.append("Pool uses tx.origin (highly unusual)")

        # Signal 4: external CALL opcodes in pool (potential callback exploit)
        calls = analyzer.extract_external_calls()
        if len(calls) > 5:
            score += 10
            signals.append(f"{len(calls)} external CALL opcodes (potential callbacks)")

        return PoolRiskReport(
            address=pool_address,
            risk_score=min(score, 100),
            detection_signals=signals,
            token0=token0,
            token1=token1,
        )

    def _get_pool_tokens(self, pool_address: str) -> tuple[str, str]:
        """Call token0() and token1() on the pool contract."""
        if not w3:
            return "", ""
        try:
            addr = w3.to_checksum_address(pool_address)
            t0_data = w3.eth.call({"to": addr, "data": "0x" + TOKEN0_SELECTOR})
            t1_data = w3.eth.call({"to": addr, "data": "0x" + TOKEN1_SELECTOR})
            token0 = "0x" + t0_data[-20:].hex()
            token1 = "0x" + t1_data[-20:].hex()
            return token0, token1
        except Exception:
            return "", ""

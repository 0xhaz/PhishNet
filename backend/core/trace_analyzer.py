"""
Trace-Guided Analysis — SKANF-inspired.

Uses historical transactions to identify which function selectors were
actually called on a contract, then cross-references with bytecode analysis
to determine if those execution paths contain tx.origin vulnerabilities.

This narrows down false positives (selectors in bytecode but never called)
and highlights real risk on actually-used code paths.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from core.bytecode_analyzer import (
    BytecodeAnalyzer,
    DANGEROUS_SELECTORS,
    ORIGIN_OPCODE,
)
from core.data_fetcher import EthDataFetcher

# Extended selector name lookup
KNOWN_SELECTORS: dict[str, str] = {
    **DANGEROUS_SELECTORS,
    "70a08231": "balanceOf(address)",
    "18160ddd": "totalSupply()",
    "dd62ed3e": "allowance(address,address)",
    "313ce567": "decimals()",
    "06fdde03": "name()",
    "95d89b41": "symbol()",
    "d0e30db0": "deposit()",
    "2e1a7d4d": "withdraw(uint256)",
    "3ccfd60b": "withdraw()",
    "e8e33700": "addLiquidity(...)",
    "f305d719": "addLiquidityETH(...)",
    "38ed1739": "swapExactTokensForTokens(...)",
    "7ff36ab5": "swapExactETHForTokens(...)",
    "18cbafe5": "swapExactTokensForETH(...)",
    "fb3bdb41": "swapETHForExactTokens(...)",
    "022c0d9f": "swap(uint256,uint256,address,bytes)",
    "6a627842": "mint(address)",
    "89afcb44": "burn(address)",
    "0902f1ac": "getReserves()",
    "bc197c81": "onERC1155BatchReceived(...)",
    "f23a6e61": "onERC1155Received(...)",
    "150b7a02": "onERC721Received(...)",
}


@dataclass
class TracedSelector:
    selector: str
    name: str | None
    call_count: int
    in_bytecode: bool
    tx_origin_nearby: bool
    risk_level: str  # "high", "medium", "low"
    sample_txns: list[str] = field(default_factory=list)


@dataclass
class TraceAnalysisResult:
    address: str
    total_transactions: int
    unique_callers: int
    traced_selectors: list[TracedSelector] = field(default_factory=list)
    vulnerable_called_count: int = 0
    uncalled_selector_count: int = 0
    risk_score: int = 0
    signals: list[str] = field(default_factory=list)


class TraceGuidedAnalyzer:
    """Cross-reference on-chain transaction history with bytecode analysis."""

    def __init__(self, fetcher: EthDataFetcher):
        self.fetcher = fetcher

    def analyze(self, address: str) -> TraceAnalysisResult:
        result = TraceAnalysisResult(address=address, total_transactions=0, unique_callers=0)

        # 1. Fetch bytecode
        try:
            bytecode = self.fetcher.get_contract_bytecode(address)
        except Exception:
            result.signals.append("Could not fetch bytecode — contract may have self-destructed")
            return result

        if len(bytecode) < 2:
            result.signals.append("No bytecode at address — likely an EOA or self-destructed contract")
            return result

        ba = BytecodeAnalyzer(bytecode)
        bytecode_selectors = ba.extract_four_byte_selectors()
        has_global_origin = ba.check_tx_origin_usage()

        # 2. Fetch recent transactions to this contract
        try:
            txns = self._get_normal_transactions(address)
        except Exception:
            result.signals.append("Could not fetch transaction history from Etherscan")
            txns = []

        result.total_transactions = len(txns)
        callers = set()
        called_selectors: Counter[str] = Counter()
        selector_txns: dict[str, list[str]] = {}

        for tx in txns:
            callers.add(tx.get("from", "").lower())
            inp = tx.get("input", "")
            if len(inp) >= 10:
                sel = inp[2:10].lower()
                called_selectors[sel] += 1
                if sel not in selector_txns:
                    selector_txns[sel] = []
                if len(selector_txns[sel]) < 3:
                    selector_txns[sel].append(tx.get("hash", ""))

        result.unique_callers = len(callers)

        # 3. Build disassembly for localized tx.origin proximity check
        origin_near_selectors = set()
        if has_global_origin:
            origin_near_selectors = self._find_selectors_near_origin(bytecode)

        # 4. Build traced selector list
        all_selectors = set(called_selectors.keys()) | bytecode_selectors
        for sel in sorted(all_selectors, key=lambda s: called_selectors.get(s, 0), reverse=True):
            in_bytecode = sel in bytecode_selectors
            was_called = sel in called_selectors
            tx_origin_nearby = sel in origin_near_selectors
            is_dangerous = sel in DANGEROUS_SELECTORS

            # Determine risk level
            if was_called and tx_origin_nearby:
                risk_level = "high"
            elif was_called and is_dangerous:
                risk_level = "high"
            elif tx_origin_nearby and not was_called:
                risk_level = "medium"
            elif not in_bytecode and was_called:
                risk_level = "low"  # called via fallback or proxy
            else:
                risk_level = "low"

            ts = TracedSelector(
                selector=sel,
                name=KNOWN_SELECTORS.get(sel),
                call_count=called_selectors.get(sel, 0),
                in_bytecode=in_bytecode,
                tx_origin_nearby=tx_origin_nearby,
                risk_level=risk_level,
                sample_txns=selector_txns.get(sel, []),
            )
            result.traced_selectors.append(ts)

        # 5. Compute stats
        result.vulnerable_called_count = sum(
            1 for ts in result.traced_selectors
            if ts.call_count > 0 and ts.tx_origin_nearby
        )
        result.uncalled_selector_count = sum(
            1 for ts in result.traced_selectors
            if ts.in_bytecode and ts.call_count == 0
        )

        # 6. Risk scoring
        score = 0
        if result.vulnerable_called_count > 0:
            score += 30
            result.signals.append(
                f"{result.vulnerable_called_count} called function(s) have tx.origin in their execution path"
            )

        dangerous_and_called = [
            ts for ts in result.traced_selectors
            if ts.call_count > 0 and ts.selector in DANGEROUS_SELECTORS and ts.tx_origin_nearby
        ]
        if dangerous_and_called:
            score += 20
            names = [DANGEROUS_SELECTORS[ts.selector] for ts in dangerous_and_called]
            result.signals.append(
                f"Dangerous functions called with tx.origin: {', '.join(names)}"
            )

        if result.unique_callers > 0 and result.unique_callers <= 3:
            score += 15
            result.signals.append(
                f"Only {result.unique_callers} unique caller(s) — suggests targeted interaction"
            )

        if result.uncalled_selector_count > 3:
            score += 10
            result.signals.append(
                f"{result.uncalled_selector_count} bytecode selectors never called — potential hidden functions"
            )

        if has_global_origin and not origin_near_selectors:
            score += 10
            result.signals.append(
                "tx.origin found in bytecode but not near any identified selector dispatch — may be in fallback"
            )

        if not result.signals:
            if has_global_origin:
                result.signals.append("tx.origin present in bytecode but not triggered by recent transactions")
            elif result.total_transactions > 0:
                result.signals.append(f"Analyzed {result.total_transactions} transactions — no tx.origin risk detected")
            else:
                result.signals.append("No transaction history available for trace analysis")

        result.risk_score = min(score, 100)
        return result

    def _get_normal_transactions(self, address: str) -> list[dict]:
        """Fetch normal (external) transactions to a contract via Etherscan."""
        return self.fetcher._etherscan(
            {
                "module": "account",
                "action": "txlist",
                "address": address,
                "sort": "desc",
                "page": "1",
                "offset": "200",
            },
            allow_empty=True,
        )

    def _find_selectors_near_origin(self, bytecode: bytes) -> set[str]:
        """Find PUSH4 selectors that appear within ~150 instructions of an ORIGIN opcode."""
        code = bytecode
        selectors_near: set[str] = set()

        # First pass: find all ORIGIN opcode positions
        origin_offsets: list[int] = []
        i = 0
        while i < len(code):
            op = code[i]
            if op == ORIGIN_OPCODE:
                origin_offsets.append(i)
            if 0x60 <= op <= 0x7F:
                i += op - 0x5F
            i += 1

        if not origin_offsets:
            return selectors_near

        # Second pass: find PUSH4 selectors and check proximity to ORIGIN
        PROXIMITY = 300  # bytes
        i = 0
        while i < len(code) - 4:
            op = code[i]
            if op == 0x63:  # PUSH4
                sel = code[i + 1: i + 5].hex()
                # Check if any ORIGIN opcode is within proximity
                for orig_off in origin_offsets:
                    if abs(i - orig_off) < PROXIMITY:
                        selectors_near.add(sel)
                        break
                i += 5
                continue
            if 0x60 <= op <= 0x7F:
                i += op - 0x5F
            i += 1

        return selectors_near

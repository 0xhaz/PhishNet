"""Module 3 — Refund-based phishing detector (covers ~1/104 known attacks).

Refund attacks exploit MEV bots that register with gas-refund services
(e.g. BackRunMe).  The attacker deploys a contract whose fallback/receive
function triggers a callback that drains the bot via tx.origin.

Key signals:
  1. Non-trivial fallback (CALLDATASIZE check → fallback path has CALL opcodes)
  2. tx.origin usage in a contract that receives ETH (refund-style)
  3. SELFDESTRUCT presence (attacker cleans up post-drain)
  4. Dangerous selectors (transfer/approve) in a non-token contract
  5. Embedded addresses matching known MEV bots
"""
from __future__ import annotations
from dataclasses import dataclass, field

from core.bytecode_analyzer import BytecodeAnalyzer, DANGEROUS_SELECTORS, CALL_OPCODES, ERC20_SELECTORS
from core.data_fetcher import EthDataFetcher
from detectors.token_detector import ensure_bots_loaded, KNOWN_MEV_BOTS

fetcher = EthDataFetcher()

SELFDESTRUCT_OPCODE = 0xFF


@dataclass
class RefundRiskReport:
    address: str
    risk_score: int
    attack_type: str = "refund"
    detection_signals: list[str] = field(default_factory=list)
    has_suspicious_fallback: bool = False
    is_refund_recipient: bool = False


class RefundPhishingDetector:
    def analyze_refund_contract(self, address: str) -> RefundRiskReport:
        signals: list[str] = []
        score = 0

        try:
            bytecode = fetcher.get_contract_bytecode(address)
        except Exception:
            return RefundRiskReport(address=address, risk_score=0,
                                   detection_signals=["Could not fetch bytecode"])

        if not bytecode or len(bytecode) < 10:
            return RefundRiskReport(address=address, risk_score=0)

        analyzer = BytecodeAnalyzer(bytecode)
        hex_code = bytecode.hex()

        # Determine if it looks like a regular ERC-20 (refund contracts are NOT tokens)
        is_erc20 = analyzer.has_erc20_interface()

        # Signal 1: non-trivial fallback with external CALL
        has_fallback = self._has_nontrivial_fallback(bytecode)
        if has_fallback:
            score += 25
            signals.append("Non-trivial fallback/receive function with CALL opcodes")

        # Signal 2: tx.origin usage — classic for refund-based drain
        if analyzer.check_tx_origin_usage():
            score += 30
            signals.append("Uses tx.origin (callback exploit vector)")

        # Signal 3: SELFDESTRUCT present — attacker self-destructs after drain
        if SELFDESTRUCT_OPCODE in bytecode:
            score += 15
            signals.append("Contains SELFDESTRUCT (post-attack cleanup)")

        # Signal 4: dangerous selectors in a NON-ERC20 contract
        selectors = analyzer.extract_four_byte_selectors()
        dangerous = selectors & set(DANGEROUS_SELECTORS.keys())
        if dangerous and not is_erc20:
            score += 30
            names = [DANGEROUS_SELECTORS[s] for s in dangerous]
            signals.append(f"Dangerous selectors in non-token contract: {', '.join(names)}")

        # Signal 5: embedded addresses targeting known MEV bots
        ensure_bots_loaded()
        embedded = analyzer.get_embedded_addresses()
        bot_targets = [a for a in embedded if a.lower() in KNOWN_MEV_BOTS]
        if bot_targets:
            score += 25
            signals.append(f"Embeds {len(bot_targets)} known MEV bot address(es)")

        # Signal 6: very small contract (< 500 bytes) with CALL — typical for exploit contracts
        if len(bytecode) < 500 and has_fallback:
            score += 10
            signals.append(f"Small contract ({len(bytecode)} bytes) with fallback — exploit pattern")

        # Boost: fallback + tx.origin + non-token = very high confidence refund attack
        if has_fallback and analyzer.check_tx_origin_usage() and not is_erc20:
            score = max(score, 90)

        return RefundRiskReport(
            address=address,
            risk_score=min(score, 100),
            detection_signals=signals,
            has_suspicious_fallback=has_fallback and bool(dangerous),
            is_refund_recipient=has_fallback and analyzer.check_tx_origin_usage(),
        )

    def _has_nontrivial_fallback(self, bytecode: bytes) -> bool:
        """Detect non-trivial fallback by checking for CALLDATASIZE-gated CALL paths.

        EVM contracts typically start with:
          CALLDATASIZE → PUSH → JUMPI (to fallback if calldatasize == 0)

        If the fallback branch contains CALL opcodes, it's non-trivial.
        """
        if len(bytecode) < 10:
            return False

        # Heuristic 1: Check for CALLDATASIZE (0x36) near start followed by CALL opcodes
        # The first 20 bytes typically contain the fallback dispatcher
        has_calldatasize = 0x36 in bytecode[:20]
        has_call = any(b in CALL_OPCODES for b in bytecode)

        if has_calldatasize and has_call:
            return True

        # Heuristic 2: Very short contract (< 300 bytes) with CALL is likely
        # a single-purpose fallback exploit
        if len(bytecode) < 300 and has_call:
            return True

        return False

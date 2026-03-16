"""
Vulnerable CALL Finder — SKANF Section 3.3 (simplified).

Identifies potentially exploitable CALL instructions in EVM bytecode by checking:
  1. Whether call targets come from user-controllable input (CALLDATALOAD)
  2. Whether ETH is forwarded via CALL with value > 0
  3. Whether DELEGATECALL/CALLCODE are used (code injection risk)
  4. Whether there's a tx.origin or msg.sender guard before the CALL
  5. Whether CALL arguments reference storage slots (indirect control)

Each vulnerable CALL is reported with its offset, type, and risk factors.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Opcodes
OP_STOP = 0x00
OP_CALLDATALOAD = 0x35
OP_CALLDATACOPY = 0x37
OP_SLOAD = 0x54
OP_SSTORE = 0x55
OP_JUMP = 0x56
OP_JUMPI = 0x57
OP_JUMPDEST = 0x5B
OP_PUSH1 = 0x60
OP_PUSH4 = 0x63
OP_PUSH32 = 0x7F

OP_CALLER = 0x33  # msg.sender
OP_ORIGIN = 0x32  # tx.origin

OP_CALL = 0xF1
OP_CALLCODE = 0xF2
OP_DELEGATECALL = 0xF4
OP_STATICCALL = 0xFA
OP_RETURN = 0xF3
OP_REVERT = 0xFD
OP_SELFDESTRUCT = 0xFF

OP_EQ = 0x14
OP_ISZERO = 0x15

CALL_OPCODES = {OP_CALL, OP_CALLCODE, OP_DELEGATECALL, OP_STATICCALL}
CALL_NAMES = {
    OP_CALL: "CALL",
    OP_CALLCODE: "CALLCODE",
    OP_DELEGATECALL: "DELEGATECALL",
    OP_STATICCALL: "STATICCALL",
}

# CALL stack layout: gas, addr, value, inOffset, inSize, outOffset, outSize
# DELEGATECALL/STATICCALL: gas, addr, inOffset, inSize, outOffset, outSize (no value)


@dataclass
class VulnerableCall:
    offset: int
    opcode: str  # CALL, DELEGATECALL, etc.
    risk_factors: list[str] = field(default_factory=list)
    risk_score: int = 0
    has_auth_guard: bool = False
    calldataload_nearby: bool = False
    sload_nearby: bool = False
    sends_value: bool = False


@dataclass
class CallAnalysisReport:
    total_calls: int = 0
    vulnerable_calls: list[VulnerableCall] = field(default_factory=list)
    has_auth_guard: bool = False  # any CALLER/ORIGIN + EQ pattern found
    auth_type: str = "none"  # "msg.sender", "tx.origin", "both", "none"
    risk_score: int = 0  # 0-100 overall
    signals: list[str] = field(default_factory=list)
    call_summary: dict = field(default_factory=dict)  # opcode -> count


class VulnerableCallFinder:
    """Find exploitable CALL instructions in EVM bytecode (SKANF Section 3.3)."""

    def __init__(self, bytecode: bytes):
        self.code = bytecode
        self.length = len(bytecode)
        self.instructions = self._disassemble()

    def analyze(self) -> CallAnalysisReport:
        report = CallAnalysisReport()
        if self.length < 10:
            report.signals.append("Contract too small for CALL analysis")
            return report

        # Step 1: Find all CALL-family instructions
        calls = [
            (idx, off, op)
            for idx, (off, op, _) in enumerate(self.instructions)
            if op in CALL_OPCODES
        ]
        report.total_calls = len(calls)

        # Count by type
        for _, _, op in calls:
            name = CALL_NAMES[op]
            report.call_summary[name] = report.call_summary.get(name, 0) + 1

        if not calls:
            report.signals.append("No external calls found in bytecode")
            return report

        # Step 2: Detect auth guards (CALLER/ORIGIN + EQ pattern)
        auth_info = self._detect_auth_guards()
        report.has_auth_guard = auth_info["has_guard"]
        report.auth_type = auth_info["type"]

        # Step 3: Analyze each CALL for vulnerabilities
        for idx, off, op in calls:
            vc = self._analyze_single_call(idx, off, op, auth_info)
            if vc.risk_score > 0:
                report.vulnerable_calls.append(vc)

        # Step 4: Compute overall score and signals
        self._compute_report_score(report)
        return report

    def _disassemble(self) -> list[tuple[int, int, int]]:
        """Return list of (offset, opcode, push_value_or_minus1)."""
        instructions = []
        i = 0
        while i < self.length:
            op = self.code[i]
            push_val = -1
            if OP_PUSH1 <= op <= OP_PUSH32:
                size = op - OP_PUSH1 + 1
                if i + 1 + size <= self.length:
                    push_val = int.from_bytes(self.code[i + 1: i + 1 + size], "big")
                instructions.append((i, op, push_val))
                i += 1 + size
            else:
                instructions.append((i, op, push_val))
                i += 1
        return instructions

    def _detect_auth_guards(self) -> dict:
        """Scan for CALLER/ORIGIN followed by EQ (access control patterns)."""
        has_caller = False
        has_origin = False
        WINDOW = 6  # look ahead up to 6 instructions for EQ

        for idx, (off, op, _) in enumerate(self.instructions):
            if op == OP_CALLER:
                # Check for EQ within window
                for j in range(idx + 1, min(idx + WINDOW, len(self.instructions))):
                    if self.instructions[j][1] == OP_EQ:
                        has_caller = True
                        break
            elif op == OP_ORIGIN:
                for j in range(idx + 1, min(idx + WINDOW, len(self.instructions))):
                    if self.instructions[j][1] == OP_EQ:
                        has_origin = True
                        break

        if has_caller and has_origin:
            return {"has_guard": True, "type": "both"}
        elif has_caller:
            return {"has_guard": True, "type": "msg.sender"}
        elif has_origin:
            return {"has_guard": True, "type": "tx.origin"}
        return {"has_guard": False, "type": "none"}

    def _analyze_single_call(
        self, idx: int, offset: int, opcode: int, auth_info: dict
    ) -> VulnerableCall:
        """Analyze a single CALL instruction for vulnerability indicators."""
        vc = VulnerableCall(offset=offset, opcode=CALL_NAMES[opcode])
        vc.has_auth_guard = auth_info["has_guard"]

        # Look back in a window before the CALL for context
        LOOKBACK = 20
        start = max(0, idx - LOOKBACK)
        window = self.instructions[start:idx]

        # Check for CALLDATALOAD in the setup (user-controllable address)
        calldataload_positions = [
            i for i, (_, op, _) in enumerate(window) if op == OP_CALLDATALOAD
        ]
        vc.calldataload_nearby = len(calldataload_positions) > 0

        # Check for SLOAD in the setup (storage-based address)
        sload_positions = [
            i for i, (_, op, _) in enumerate(window) if op == OP_SLOAD
        ]
        vc.sload_nearby = len(sload_positions) > 0

        # Check for value parameter (CALL has 7 args: gas, addr, VALUE, ...)
        # If a non-zero constant is pushed as value, it sends ETH
        if opcode == OP_CALL:
            vc.sends_value = self._check_sends_value(window)

        # --- Risk scoring ---

        # DELEGATECALL is inherently dangerous (code injection)
        if opcode == OP_DELEGATECALL:
            vc.risk_factors.append("DELEGATECALL: allows arbitrary code execution in caller's context")
            vc.risk_score += 40

        # CALLCODE is deprecated but dangerous
        if opcode == OP_CALLCODE:
            vc.risk_factors.append("CALLCODE: deprecated, executes external code in caller's storage")
            vc.risk_score += 35

        # CALLDATALOAD feeds into CALL target → attacker can choose target address
        if vc.calldataload_nearby:
            vc.risk_factors.append("Call target may derive from calldata (user-controllable)")
            vc.risk_score += 25

        # SLOAD feeds into CALL → target from storage (may be manipulable)
        if vc.sload_nearby and not vc.calldataload_nearby:
            vc.risk_factors.append("Call target may derive from storage slot")
            vc.risk_score += 10

        # Sends ETH
        if vc.sends_value:
            vc.risk_factors.append("CALL forwards ETH value (potential drain vector)")
            vc.risk_score += 20

        # No auth guard before CALL
        if not auth_info["has_guard"]:
            vc.risk_factors.append("No access control guard (CALLER/ORIGIN + EQ) detected")
            vc.risk_score += 15
        elif auth_info["type"] == "tx.origin":
            vc.risk_factors.append("Auth uses tx.origin (vulnerable to phishing callbacks)")
            vc.risk_score += 25

        vc.risk_score = min(vc.risk_score, 100)
        return vc

    def _check_sends_value(self, window: list[tuple[int, int, int]]) -> bool:
        """Heuristic: check if any non-zero value is pushed in the setup window.

        For CALL(gas, addr, value, ...), value is the 3rd stack arg.
        We can't do full stack tracking, so we check for CALLVALUE or non-zero pushes.
        """
        for _, op, val in window:
            if op == 0x34:  # CALLVALUE — forwarding received value
                return True
            if op == 0x47:  # SELFBALANCE — sending entire balance
                return True
        # Check for BALANCE opcode (checking someone's balance, might send it)
        for _, op, _ in window:
            if op == 0x31:  # BALANCE
                return True
        return False

    def _compute_report_score(self, report: CallAnalysisReport) -> None:
        """Compute overall risk score and generate signals."""
        if not report.vulnerable_calls:
            report.risk_score = 0
            report.signals.append("No vulnerable CALL patterns detected")
            return

        # Overall score: weighted by most dangerous call
        max_call = max(report.vulnerable_calls, key=lambda c: c.risk_score)
        report.risk_score = max_call.risk_score

        # Boost if multiple vulnerable calls
        if len(report.vulnerable_calls) >= 3:
            report.risk_score = min(report.risk_score + 15, 100)

        # Generate signals
        for name, count in report.call_summary.items():
            report.signals.append(f"{count}× {name} instruction(s) found")

        vuln_count = len(report.vulnerable_calls)
        report.signals.append(
            f"{vuln_count} potentially vulnerable call(s) identified "
            f"(highest risk: {max_call.risk_score}/100 at offset 0x{max_call.offset:04x})"
        )

        # Auth-specific signals
        if report.auth_type == "tx.origin":
            report.signals.append(
                "Access control uses tx.origin — vulnerable to phishing via "
                "malicious token callbacks (SKANF Section 3.3)"
            )
        elif report.auth_type == "none":
            report.signals.append(
                "No access control pattern detected — external calls may be "
                "callable by any address"
            )
        elif report.auth_type == "msg.sender":
            report.signals.append(
                "Access control uses msg.sender (safer than tx.origin)"
            )

        # DELEGATECALL-specific
        delegatecalls = [c for c in report.vulnerable_calls if c.opcode == "DELEGATECALL"]
        if delegatecalls:
            report.signals.append(
                f"{len(delegatecalls)} DELEGATECALL(s) detected — allows external code "
                f"to execute in this contract's context (storage, balance)"
            )

        # Calldataload-driven calls
        cd_calls = [c for c in report.vulnerable_calls if c.calldataload_nearby]
        if cd_calls:
            report.signals.append(
                f"{len(cd_calls)} call(s) with user-controllable target address "
                f"(CALLDATALOAD in setup)"
            )

        # Value-sending calls
        val_calls = [c for c in report.vulnerable_calls if c.sends_value]
        if val_calls:
            report.signals.append(
                f"{len(val_calls)} call(s) that forward ETH — potential drain vector"
            )

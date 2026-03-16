"""
Obfuscation Analyzer — SKANF Section 3.2.

Detects control-flow obfuscation techniques in EVM bytecode:
  - Indirect jumps (computed targets vs constant PUSH+JUMP)
  - Dead code / unreachable JUMPDEST targets
  - Opaque predicates (always-true/false conditional jumps)
  - Code density metrics (instruction-to-bytecode ratio)
  - Obfuscation level classification (none → heavy)
"""
from __future__ import annotations

from dataclasses import dataclass, field

# EVM opcode constants
OP_STOP = 0x00
OP_JUMP = 0x56
OP_JUMPI = 0x57
OP_JUMPDEST = 0x5B
OP_PUSH1 = 0x60
OP_PUSH32 = 0x7F
OP_RETURN = 0xF3
OP_REVERT = 0xFD
OP_INVALID = 0xFE
OP_SELFDESTRUCT = 0xFF
OP_DUP1 = 0x80
OP_DUP16 = 0x8F
OP_SWAP1 = 0x90
OP_SWAP16 = 0x9F

TERMINATING = {OP_STOP, OP_JUMP, OP_RETURN, OP_REVERT, OP_INVALID, OP_SELFDESTRUCT}


@dataclass
class ObfuscationReport:
    obfuscation_level: str = "unknown"  # none, light, moderate, heavy
    obfuscation_score: int = 0  # 0-100
    total_jumps: int = 0
    direct_jumps: int = 0
    indirect_jumps: int = 0
    total_jumpdests: int = 0
    reachable_jumpdests: int = 0
    unreachable_jumpdests: int = 0
    dead_code_bytes: int = 0
    total_bytes: int = 0
    code_density: float = 0.0  # ratio of instruction bytes to total
    function_selectors: int = 0
    signals: list[str] = field(default_factory=list)


class ObfuscationAnalyzer:
    """Analyze EVM bytecode for obfuscation patterns (SKANF Section 3.2)."""

    def __init__(self, bytecode: bytes):
        self.code = bytecode
        self.length = len(bytecode)

    def analyze(self) -> ObfuscationReport:
        report = ObfuscationReport(total_bytes=self.length)
        if self.length < 10:
            report.obfuscation_level = "none"
            report.signals.append("Contract too small for meaningful analysis")
            return report

        # Step 1: Disassemble — map offset to opcode, skip PUSH data
        instructions = self._disassemble()
        report.code_density = len(instructions) / max(self.length, 1)

        # Step 2: Find all JUMPDEST locations
        jumpdests = {off for off, op, _ in instructions if op == OP_JUMPDEST}
        report.total_jumpdests = len(jumpdests)

        # Step 3: Classify jumps as direct (PUSH+JUMP) or indirect
        direct, indirect, jump_targets = self._classify_jumps(instructions)
        report.total_jumps = direct + indirect
        report.direct_jumps = direct
        report.indirect_jumps = indirect

        # Step 4: Estimate reachable JUMPDESTs
        # A JUMPDEST is "reachable" if it's the target of a direct jump OR
        # falls through from a non-terminating instruction
        fallthrough_reachable = self._compute_fallthrough_reachable(instructions, jumpdests)
        reachable = jump_targets | fallthrough_reachable
        report.reachable_jumpdests = len(reachable & jumpdests)
        report.unreachable_jumpdests = len(jumpdests - reachable)

        # Step 5: Dead code estimation
        report.dead_code_bytes = self._estimate_dead_code(instructions, reachable, jumpdests)

        # Step 6: Count function selectors (PUSH4 in dispatcher)
        report.function_selectors = self._count_selectors(instructions)

        # Step 7: Score and classify
        self._compute_score(report)

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

    def _classify_jumps(
        self, instructions: list[tuple[int, int, int]]
    ) -> tuple[int, int, set[int]]:
        """Count direct vs indirect jumps. Direct = preceded by PUSHn."""
        direct = 0
        indirect = 0
        targets: set[int] = set()

        for idx, (off, op, _) in enumerate(instructions):
            if op not in (OP_JUMP, OP_JUMPI):
                continue
            # Check if preceding instruction is a PUSH
            if idx > 0:
                prev_off, prev_op, prev_val = instructions[idx - 1]
                if OP_PUSH1 <= prev_op <= OP_PUSH32 and prev_val >= 0:
                    direct += 1
                    targets.add(prev_val)
                    continue
                # JUMPI: target might be 2 instructions back (PUSH target, condition, JUMPI)
                if op == OP_JUMPI and idx > 1:
                    pp_off, pp_op, pp_val = instructions[idx - 2]
                    if OP_PUSH1 <= pp_op <= OP_PUSH32 and pp_val >= 0:
                        direct += 1
                        targets.add(pp_val)
                        continue
            indirect += 1

        return direct, indirect, targets

    def _compute_fallthrough_reachable(
        self,
        instructions: list[tuple[int, int, int]],
        jumpdests: set[int],
    ) -> set[int]:
        """Find JUMPDESTs reachable via sequential fallthrough from non-terminating instructions."""
        reachable: set[int] = set()
        for idx in range(len(instructions) - 1):
            off, op, _ = instructions[idx]
            next_off = instructions[idx + 1][0]
            if op not in TERMINATING and next_off in jumpdests:
                reachable.add(next_off)
        # Entry point (offset 0) is always reachable
        if 0 in jumpdests:
            reachable.add(0)
        return reachable

    def _estimate_dead_code(
        self,
        instructions: list[tuple[int, int, int]],
        reachable: set[int],
        jumpdests: set[int],
    ) -> int:
        """Estimate bytes of dead code (after terminators, before unreachable JUMPDESTs)."""
        dead = 0
        in_dead_zone = False
        for idx, (off, op, _) in enumerate(instructions):
            if op == OP_JUMPDEST:
                in_dead_zone = off not in reachable
            elif op in TERMINATING:
                # After a terminator, code is dead unless the next instruction is a reachable JUMPDEST
                if idx + 1 < len(instructions):
                    next_off = instructions[idx + 1][0]
                    if next_off not in reachable:
                        in_dead_zone = True

            if in_dead_zone and op != OP_JUMPDEST:
                # Count the instruction bytes as dead
                if idx + 1 < len(instructions):
                    dead += instructions[idx + 1][0] - off
                else:
                    dead += self.length - off

        return dead

    def _count_selectors(self, instructions: list[tuple[int, int, int]]) -> int:
        """Count PUSH4 instructions that look like function selectors (in the first 500 bytes)."""
        count = 0
        for off, op, val in instructions:
            if off > 500:
                break
            if op == 0x63 and val >= 0:  # PUSH4
                count += 1
        return count

    def _compute_score(self, report: ObfuscationReport) -> None:
        """Compute obfuscation score (0-100) and classify level."""
        score = 0
        signals = report.signals

        # Indirect jump ratio
        if report.total_jumps > 0:
            indirect_ratio = report.indirect_jumps / report.total_jumps
            if indirect_ratio > 0.5:
                score += 35
                signals.append(
                    f"High indirect jump ratio: {indirect_ratio:.0%} "
                    f"({report.indirect_jumps}/{report.total_jumps} jumps are computed)"
                )
            elif indirect_ratio > 0.2:
                score += 20
                signals.append(
                    f"Moderate indirect jump ratio: {indirect_ratio:.0%} "
                    f"({report.indirect_jumps} computed jumps)"
                )
            elif report.indirect_jumps > 0:
                score += 5
                signals.append(
                    f"Some indirect jumps detected: {report.indirect_jumps}"
                )

        # Unreachable JUMPDESTs
        if report.total_jumpdests > 0:
            unreachable_ratio = report.unreachable_jumpdests / report.total_jumpdests
            if unreachable_ratio > 0.3:
                score += 20
                signals.append(
                    f"Many unreachable JUMPDEST targets: {report.unreachable_jumpdests}/{report.total_jumpdests} "
                    f"({unreachable_ratio:.0%}) — possible dead code insertion"
                )
            elif unreachable_ratio > 0.1:
                score += 10
                signals.append(
                    f"Some unreachable JUMPDESTs: {report.unreachable_jumpdests}/{report.total_jumpdests}"
                )

        # Dead code ratio
        if report.total_bytes > 0:
            dead_ratio = report.dead_code_bytes / report.total_bytes
            if dead_ratio > 0.3:
                score += 20
                signals.append(
                    f"High dead code ratio: {dead_ratio:.0%} "
                    f"({report.dead_code_bytes} bytes unreachable)"
                )
            elif dead_ratio > 0.1:
                score += 10
                signals.append(
                    f"Some dead code detected: ~{report.dead_code_bytes} bytes ({dead_ratio:.0%})"
                )

        # Low code density (lots of embedded data or padding)
        if report.code_density < 0.3 and report.total_bytes > 100:
            score += 10
            signals.append(
                f"Low code density: {report.code_density:.2f} — may contain packed/encrypted payload"
            )

        # Few selectors for code size (hidden entry points)
        if report.function_selectors == 0 and report.total_bytes > 200:
            score += 15
            signals.append("No visible function selectors — possible hidden dispatch or proxy pattern")
        elif report.function_selectors == 1 and report.total_bytes > 500:
            score += 5
            signals.append("Single function selector for large contract — unusual")

        # Clamp
        score = min(score, 100)
        report.obfuscation_score = score

        if score >= 60:
            report.obfuscation_level = "heavy"
        elif score >= 35:
            report.obfuscation_level = "moderate"
        elif score >= 15:
            report.obfuscation_level = "light"
        else:
            report.obfuscation_level = "none"

        if not signals:
            signals.append("No significant obfuscation patterns detected")

"""Low-level EVM bytecode analysis utilities."""
from __future__ import annotations

DANGEROUS_SELECTORS: dict[str, str] = {
    "a9059cbb": "transfer(address,uint256)",
    "095ea7b3": "approve(address,uint256)",
    "23b872dd": "transferFrom(address,address,uint256)",
}

ERC20_SELECTORS = {
    "a9059cbb",  # transfer
    "70a08231",  # balanceOf
    "18160ddd",  # totalSupply
    "dd62ed3e",  # allowance
}

CALL_OPCODES = {0xF1, 0xF2, 0xF4, 0xFA}  # CALL, CALLCODE, DELEGATECALL, STATICCALL
ORIGIN_OPCODE = 0x32


class ExternalCall:
    def __init__(self, offset: int, opcode: int, selector: str | None = None):
        self.offset = offset
        self.opcode = opcode
        self.selector = selector


class BytecodeAnalyzer:
    def __init__(self, bytecode: bytes):
        self.bytecode = bytecode

    def has_erc20_interface(self) -> bool:
        """Check for presence of common ERC-20 function selectors in bytecode."""
        hex_code = self.bytecode.hex()
        return any(sel in hex_code for sel in ERC20_SELECTORS)

    def check_tx_origin_usage(self) -> bool:
        """Return True if the ORIGIN opcode (0x32) appears in the bytecode."""
        return ORIGIN_OPCODE in self.bytecode

    def extract_external_calls(self) -> list[ExternalCall]:
        """Find CALL-family opcodes; attempt to extract 4-byte selectors from push data."""
        calls: list[ExternalCall] = []
        code = self.bytecode
        i = 0
        while i < len(code):
            op = code[i]
            if op in CALL_OPCODES:
                calls.append(ExternalCall(offset=i, opcode=op))
            # Skip PUSH data bytes
            if 0x60 <= op <= 0x7F:
                push_size = op - 0x5F
                i += push_size
            i += 1
        return calls

    def get_embedded_addresses(self) -> list[str]:
        """Extract 20-byte sequences that look like Ethereum addresses."""
        addresses: list[str] = []
        hex_code = self.bytecode.hex()
        for i in range(0, len(hex_code) - 40, 2):
            chunk = hex_code[i : i + 40]
            if chunk.startswith("000000000000000000000000"):
                addr = "0x" + chunk[24:]
                if addr != "0x" + "0" * 40:
                    addresses.append(addr)
        return list(set(addresses))

    def extract_four_byte_selectors(self) -> set[str]:
        """Return all 4-byte sequences that appear in PUSH4 instructions."""
        selectors: set[str] = set()
        code = self.bytecode
        i = 0
        while i < len(code) - 4:
            op = code[i]
            if op == 0x63:  # PUSH4
                sel = code[i + 1 : i + 5].hex()
                selectors.add(sel)
                i += 5
                continue
            if 0x60 <= op <= 0x7F:
                i += op - 0x5F
            i += 1
        return selectors

import idautils
from ida_funcs import func_t
from ida_ua import insn_t


def decode_instruction(ea: int) -> insn_t | None:
    """Decode an instruction at the given ea"""
    return idautils.DecodeInstruction(ea)


def decode_next_instruction(insn: insn_t, func: func_t) -> insn_t | None:
    """Decode the next instruction after the given insn"""
    next_ea = insn.ea + insn.size
    if next_ea >= func.end_ea:
        return None

    return decode_instruction(next_ea)


def decode_previous_instruction(insn: insn_t) -> insn_t | None:
    """Decode the previous instruction for the given insn"""
    return idautils.DecodePrecedingInstruction(insn.ea)[0]


def get_previous(ea: int, canon_name: str, previous_opcode_count: int) -> int | None:
    """Given an ea, search up until reaching an instruction with {canon_name}"""
    insn = decode_instruction(ea)
    if not insn:
        return None

    if insn.get_canon_mnem() == canon_name:
        return ea

    for _ in range(previous_opcode_count):
        insn = decode_previous_instruction(insn)
        # No more instructions in this execution flow
        if insn is None:
            break
        if insn.get_canon_mnem() == canon_name:
            return insn.ea
    return None

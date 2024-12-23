"""
Based on: https://hex-rays.com/blog/improving-ida-analysis
"""
import enum
import logging

import ida_bytes
import ida_idp
import ida_ua


class ITypes(enum.IntEnum):
    UNK0 = ida_idp.CUSTOM_INSN_ITYPE + 16
    UNK1 = enum.auto()


UNK_ITYPES = set(ITypes)
UNK_INSNS = {
    0x04BF5828: ITypes.UNK0,
    0xD5033A3F: ITypes.UNK1,  # Some ISB variant?
}
INSN_SIZE = 4


class IDPHooks(ida_idp.IDP_Hooks):

    def __init__(self):
        super().__init__()
        self.log = logging.getLogger(self.__class__.__name__)
        self.visited = set()

    def ev_ana_insn(self, insn: ida_ua.insn_t) -> int:
        ea = insn.ea
        encoded_insn = ida_bytes.get_dword(ea)
        if encoded_insn in UNK_INSNS:

            if ea not in self.visited:
                self.log.info(f'UNK INSN {encoded_insn:#x} found at {ea:#x}')
                self.visited.add(ea)

            insn.itype = UNK_INSNS[encoded_insn].value
            insn.size = INSN_SIZE

            insn_bytes = ' '.join(f'{c:02X}' for c in ida_bytes.get_bytes(insn.ea, INSN_SIZE))
            ida_bytes.set_cmt(insn.ea, f'IDA could not decode this instruction! {insn_bytes}', True)
            return INSN_SIZE
        return 0

    def ev_out_mnem(self, ctx: ida_ua.outctx_t) -> int:
        if ctx.insn.itype in UNK_ITYPES:
            ctx.out_custom_mnem(ITypes(ctx.insn.itype).name, width=4)
            return 1
        return 0

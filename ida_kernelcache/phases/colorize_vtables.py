import ida_bytes
import ida_nalt
from .base_phase import BasePhase
from .. import consts
from ..exceptions import PhaseException


class ColorizeVtables(BasePhase):
    """
    The idea was to change the background color of every vtable entry according to its flags.
    This help visualize the RTTI information we gathered so far, which can later be explored by a researcher
    I found it also very useful to set a comment showing the PAC diversifier near each vtable entry
    """

    def __init__(self, kc):
        super().__init__(kc)

    def run(self):
        no_vtables = 0
        total = 0
        for class_info in self._kc.class_info_map.values():
            if class_info.vtable_info is None:
                no_vtables += 1
                continue

            for vtable_entry in class_info.vtable_info.entries:
                total += 1

                if vtable_entry.inherited:
                    bgcolor = consts.BGCOLOR_GRAY
                    cmt = 'inherited'
                elif vtable_entry.overrides:
                    bgcolor = consts.BGCOLOR_RED
                    cmt = 'overrides'
                elif vtable_entry.added:
                    bgcolor = consts.BGCOLOR_GREEN
                    cmt = 'added'
                else:
                    raise PhaseException(f'Invalid vtable entry flags!')

                # This doesn't really happen for IDBs that were just now analyzed by IDA.
                # I check to see that the item is a QWORD because I want each vtable entry to be on its own line
                # so that I can determine the background color in a fine granularity (i.e. control the bgcolor of every vtable entry independently of others)
                # If I would choose to change the type information to match the {class_name}_vtbl structure we have created, then we would lose the ability to do this
                # Unless IDA provides some API which is similar to set_array_parameters (in idc) where I can determine the number of items per line in the representation
                # of structure in the data segments.
                if not ida_bytes.get_flags(vtable_entry.entry_ea) & ida_bytes.FF_QWORD:
                    self.log.error(f'{vtable_entry.entry_ea:#x} is not a QWORD data type!')
                    continue

                ida_nalt.set_item_color(vtable_entry.entry_ea, bgcolor)
                ida_bytes.set_cmt(vtable_entry.entry_ea, f'{cmt} PAC:{vtable_entry.pac_diversifier:#x}', True)

        self.log.info(f'Colored {total} lines of vtable entries')

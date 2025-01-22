import ida_hexrays
import ida_xref
import idc

import ida_kernelcache.consts as consts
import ida_kernelcache.symbols as symbols
import ida_kernelcache.ida_helpers.names as names
from .base_phase import BasePhase

from typing import TYPE_CHECKING

from ..exceptions import PhaseException
from ..ida_helpers import strings, functions, decompiler

if TYPE_CHECKING:
    from ida_kernelcache.rtti import ClassInfo


class ApplyRTTIInfoPhase(BasePhase):
    """
    Populate IDA with symbols according to the OSMetaClass metadata we've gained so far!
    In high-level this phase will the following:

    - instance symbols for an iOS kernelcache.
    - Search through the kernelcache for OSMetaClass instances and add a symbol for each known instance
    - Populate IDA with virtual method table symbols
    """
    DYNAMIC_CAST_PANIC = '\"OSDynamicCast(AGXAccelerator, driverService)\" @%s:%d'

    def __init__(self, kc):
        super().__init__(kc)

    def run(self):
        for classname, classinfo in self._kc.class_info_map.items_by_type(str):
            if consts.CXX_SCOPE in classname:
                self.log.warning(f'Skipping symbolication of {classname} because it contains {consts.CXX_SCOPE}!')
                continue

            self._add_metaclass_instance_symbol(classinfo)

            # TODO: is this really how we want to handle classes without vtable information? Maybe we should use their superclass's vtable
            if classinfo.vtable_info:
                self._add_vtable_symbol(classinfo)
            else:
                self.log.debug(f'Skipping vtable symbol for {classname} because we dont have the corresponding vtable ea!')

    def _find_safemetacast(self):
        """
        We must first find the EA for OSMetaClass::safeMetaCast
        TODO: finish implementing this!
        """
        panic_str_ea = strings.find_str(self.DYNAMIC_CAST_PANIC).ea
        xref_ea = ida_xref.get_first_cref_to(panic_str_ea)
        if xref_ea == idc.BADADDR:
            raise PhaseException(f'No xref found for {panic_str_ea:#x}')

        if ida_xref.get_next_cref_to(panic_str_ea, xref_ea) != idc.BADADDR:
            raise PhaseException(f'More than 1 xref to {panic_str_ea:#x}')

        func_start = functions.get_func_start(xref_ea, raise_error=True)
        cfunc = ida_hexrays.decompile(func_start)
        if cfunc is None:
            raise PhaseException(f'Failed decompilation of {func_start:#x}')

        visitor = decompiler.FindCallByArgVisitor(panic_str_ea)
        visitor.apply_to(cfunc.body, None)
        if not visitor.found:
            raise PhaseException("Failed to find panic call!")

    def _add_metaclass_instance_symbol(self, classinfo: 'ClassInfo') -> None:
        """
        Add a symbol for the OSMetaClass instance at the specified address.
        """
        metaclass_instance_symbol = symbols.metaclass_symbol_for_class(classinfo.class_name)
        ea = classinfo.metaclass_ea
        if not names.set_ea_name(ea, metaclass_instance_symbol, rename=True):
            self.log.error(f'Failed to set name at {classinfo.metaclass_ea:#x}! wanted {metaclass_instance_symbol}')

    def _add_vtable_symbol(self, classinfo: 'ClassInfo') -> None:
        """
        Set a symbol for the virtual method table at the specified address, renaming it if it already exists!
        """
        vtable_symbol = symbols.vtable_symbol_for_class(classinfo.class_name)
        if not names.set_ea_name(classinfo.vtable_info.vtable_ea, vtable_symbol, rename=True):
            self.log.error(f'Failed to set name at {classinfo.vtable_info.vtable_ea:#x}! wanted {vtable_symbol}')

    def _symbolicate_overrides_for_classinfo(self):
        # TODO: implement this?
        raise NotImplementedError()

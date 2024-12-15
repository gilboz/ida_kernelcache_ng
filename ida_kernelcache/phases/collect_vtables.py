import re
from itertools import islice, takewhile

import idaapi
import idautils
import idc

from .base_phase import BasePhase
from ida_kernelcache import (
    ida_utilities as idau,
    symbol,
    consts
)
from ida_kernelcache.emulate import emulate_arm64
from ida_kernelcache.exceptions import PhaseException
from ida_kernelcache.utils import OneToOneMapFactory


class CollectVtables(BasePhase):
    """
    This phase depends on the CollectClasses phase and must run after it
    """

    def __init__(self, kc):
        super().__init__(kc)

        # Build a mapping from OSMetaClass instances to virtual method tables.
        self._metaclass_to_vtable_builder = OneToOneMapFactory()
        self._vtables = {}  # Map vtable ea to vtable length
        self._metaclass_info = {}  # Map class name (str) to ClassInfo instance without vtable information

    def run(self):
        if not len(self._kc.classes):
            raise PhaseException(f"There are no entries in the KernelCache.classes dictionary.. consider running "
                                 f"CollectClasses phase before {self.__class__}")

        self._metaclass_info = self._kc.classes.copy()

        assert (len(self._metaclass_info) > 0)

        self.log(1, 'Searching for virtual method tables')
        classes = self._collect_vtables()
        if not classes:
            raise PhaseException('Could not collect virtual method tables')
        self.log(0, f'Lost {len(self._metaclass_info) - len(classes)} class entries in the {self.__class__} phase..')
        self._kc.vtables = self._vtables.copy()
        self._kc.classes = classes.copy()

    def _collect_vtables(self):
        """
        Use OSMetaClass information to search for virtual method tables.
        """

        # Process all the segments with found_vtable().
        for segstart in idautils.Segments():
            segname = idc.get_segm_name(segstart)
            if re.match('.*__const', segname) is None:
                continue
            self.log(2, 'Processing segment {}', segname)
            self._process_const_section_for_vtables(segstart)

        # If a metaclass has multiple vtables, that's really weird, unless the metaclass is
        # OSMetaClass's metaclass. In that case all OSMetaClass subclasses will have their vtables
        # refer back to OSMetaClass's metaclass.
        def bad_metaclass(metaclass, vtables):
            metaclass_name = self._metaclass_info[metaclass].classname
            if metaclass_name != 'OSMetaClass':
                vtinfo = ['{:#x}'.format(vt) for vt in vtables]
                self.log(0, 'Metaclass {:#x} ({}) has multiple vtables: {}', metaclass,
                         metaclass_name, ', '.join(vtinfo))

        # If a vtable has multiple metaclasses, that's really weird.
        def bad_vtable(vtable, metaclasses):
            mcinfo = ['{:#x} ({})'.format(mc, self._metaclass_info[mc].classname) for mc in metaclasses]
            self.log(0, 'Vtable {:#x} has multiple metaclasses: {}', vtable, ', '.join(mcinfo))

        metaclass_to_vtable = self._metaclass_to_vtable_builder.build(bad_metaclass, bad_vtable)

        # The resulting mapping may have fewer metaclasses than metaclass_info.
        class_info = dict()
        for metaclass, classinfo in self._metaclass_info.items():
            # Add the vtable and its length, which we didn't have earlier. If the current class doesn't
            # have a vtable, take it from the superclass (recursing if necessary).
            metaclass_with_vtable = metaclass
            while metaclass_with_vtable:
                vtable = metaclass_to_vtable.get(metaclass_with_vtable, None)
                if vtable:
                    classinfo.vtable = vtable
                    classinfo.vtable_length = self._vtables[vtable]
                    break
                classinfo_with_vtable = self._metaclass_info.get(metaclass_with_vtable, None)
                if not classinfo_with_vtable:
                    break
                metaclass_with_vtable = classinfo_with_vtable.meta_superclass
            # Set the superclass field and add the current classinfo to the superclass's children. This
            # is safe since this is the last filtering operation.
            superclass = self._metaclass_info.get(classinfo.meta_superclass, None)
            if superclass:
                classinfo.superclass = self._metaclass_info[classinfo.meta_superclass]
                classinfo.superclass.subclasses.add(classinfo)
            # Add the classinfo to the final dictionary.
            class_info[classinfo.classname] = classinfo
        return class_info

    def _found_vtable(self, metaclass, vtable, length):
        """
        Callback to register a vtable we just discovered
        """
        # Add our vtable length.
        self._vtables[vtable] = length
        # If our classname has a defined vtable symbol and that symbol's address isn't this vtable,
        # don't add the link.
        classname = self._metaclass_info[metaclass].classname
        proper_vtable_symbol = symbol.vtable_symbol_for_class(classname)
        proper_vtable_symbol_ea = idau.get_name_ea(proper_vtable_symbol)
        if proper_vtable_symbol_ea not in (idc.BADADDR, vtable) and idau.read_ptr(proper_vtable_symbol_ea) not in (
                idc.BADADDR, vtable):
            return
        # If our vtable has a symbol and it doesn't match the metaclass, skip adding a link.
        vtable_symbol = idau.get_ea_name(vtable, user=True)
        if vtable_symbol:
            vtable_classname = symbol.vtable_symbol_get_class(vtable_symbol)
            if vtable_classname != classname:
                self.log(2, 'Declining association between metaclass {:x} ({}) and vtable {:x} ({})',
                         metaclass, classname, vtable, vtable_classname)
                return

        # TODO: deprecate..
        # Add a link if they are in the same kext and the kernelcache is not MERGED.
        # if self._kc.format == KCFormat.NORMAL_11 and segment.kernelcache_kext(metaclass) != segment.kernelcache_kext(vtable):
        #     return
        self._metaclass_to_vtable_builder.add_link(metaclass, vtable)

    def _get_vtable_metaclass(self, vtable_addr):
        """
        Simulate the getMetaClass method of the vtable and check if it returns an OSMetaClass.
        TODO: can this be done using IDA's hexrays API?
        """
        getMetaClass = idau.read_word(vtable_addr + consts.VTABLE_GETMETACLASS * idau.WORD_SIZE)

        def on_RET(reg):
            on_RET.ret = reg['X0']

        on_RET.ret = None
        emulate_arm64(getMetaClass, getMetaClass + idau.WORD_SIZE * consts.MAX_GETMETACLASS_INSNS,
                      on_RET=on_RET)
        if on_RET.ret in self._metaclass_info:
            return on_RET.ret
        return None

    def _process_const_section_for_vtables(self, segstart):
        """
        Process a __const section to search for virtual method tables.
        """
        segend = idc.get_segm_end(segstart)
        addr = segstart
        while addr < segend:
            possible, length = self._vtable_length(addr, segend, scan=True)
            if possible:
                self.log(6, f"checking vtable at address: {addr:#x}")
                metaclass = self._get_vtable_metaclass(addr)
                if metaclass:
                    self.log(4, 'Vtable at address {:#x} has metaclass {:#x} and length: {:#x}', addr, metaclass, length)
                    self._found_vtable(metaclass, addr, length)
            addr += length * idau.WORD_SIZE

    def _vtable_length(self, ea, end=None, scan=False):
        """
        Find the length of a virtual method table.

        This function checks whether the effective address could correspond to a virtual method table
        and calculates its length, including the initial empty entries. By default (when scan is
        False), this function returns the length of the vtable if the address could correspond to a
        vtable, or 0 if the address definitely could not be a vtable.

        Arguments:
            ea: The linear address of the start of the vtable.

        Options:
            end: The end address to search through. Defaults to the end of the section.
            scan: Set to True to indicate that this function is being called to scan memory for virtual
                method tables. Instead of returning the length of the vtable or 0, this function will
                return a tuple (possible, length). Additionally, as a slight optimization, this
                function will sometimes look ahead in order to increase the amount of data that can be
                skipped, reducing duplication of effort between subsequent calls.

        Returns:
            If scan is False (the default), then this function returns the length of the vtable in
            words, including the initial empty entries.

            Otherwise, this function returns a tuple (possible, length). If the address could
            correspond to the start of a vtable, then possible is True and length is the length of the
            vtable in words, including the initial empty entries. Otherwise, if the address is
            definitely not the start of a vtable, then possible is False and length is the number of
            words that can be skipped when searching for the next vtable.
        """

        # TODO: This function should be reorganized. The better way of doing it is to count the number
        # of zero entries, then the number of nonzero entries, then decide based on that. Less
        # special-casing that way.
        # TODO: We should have a static=True/False flag to indicate whether we want to include the
        # empty entries.
        def return_value(possible, length):
            if scan:
                return possible, length
            return length if possible else 0

        # Initialize default values.
        if end is None:
            end = idc.get_segm_end(ea)
        words = idau.ReadWords(ea, end)
        # Iterate through the first VTABLE_OFFSET words. If any of them are nonzero, then we can skip
        # past all the words we just saw.
        for idx, word in enumerate(islice(words, consts.VTABLE_OFFSET)):
            if word != 0:
                return return_value(False, idx + 1)
        # Now this first word after the padding section is special.
        first = next(words, None)
        if first is None:
            # We have 2 zeros followed by the end of our range.
            return return_value(False, consts.VTABLE_OFFSET)
        elif first == 0:
            # We have VTABLE_OFFSET + 1 zero entries.
            zeros = consts.VTABLE_OFFSET + 1
            if scan:
                # To avoid re-reading the data we just read in the case of a zero-filled section, let's
                # look ahead a bit until we find the first non-zero value.
                for word in words:
                    if word is None:
                        return return_value(False, zeros)
                    if word != 0:
                        break
                    zeros += 1
                else:
                    # We found no nonzero words before the end.
                    return return_value(False, zeros)
            # We can skip all but the last VTABLE_OFFSET zeros.
            return return_value(False, zeros - consts.VTABLE_OFFSET)
        # TODO: We should verify that all vtable entries refer to code.
        # Now we know that we have at least one nonzero value, our job is easier. Get the full length
        # of the vtable, including the first VTABLE_OFFSET entries and the subsequent nonzero entries,
        # until either we find a zero word (not included), or an address which is not in the range of kernel addresses  or run out of words in the stream.
        info = idaapi.get_inf_structure()
        min_addr, max_addr = info.min_ea, info.max_ea
        length = consts.VTABLE_OFFSET + 1 + idau.iterlen(
            takewhile(lambda word: word != 0 and min_addr < word < max_addr, words))
        # Now it's simple: We are valid if the length is long enough, invalid if it's too short.
        return return_value(length >= consts.MIN_VTABLE_LENGTH, length)

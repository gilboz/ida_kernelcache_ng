#
# ida_kernelcache/tagged_pointers.py
# Brandon Azad
#
"""
ida_kernelcache.tagged_pointers

This module is responsible for processing the tagged pointers in the new iOS 12 kernelcache and
replacing them with their untagged equivalents. All found pointers are also converted into offsets.

In an alternative implementation, we could just add cross-references in IDA. However, I think this
approach is better because it is closer to what the kernelcache looks like at runtime.
"""
import idautils
import idc

from .base_phase import BasePhase
from ida_kernelcache import (
    ida_utilities as idau
)
from ida_kernelcache.consts import KCFormat


class TaggedPointers(BasePhase):
    START_LOG = 'Processing tagged kernelcache pointers'

    def run(self):
        assert self._kc.format == KCFormat.MERGED_12, 'Wrong kernelcache format'
        self.log(2, 'Starting tagged pointer conversion')
        for seg in idautils.Segments():
            self._untag_pointers_in_range(idc.get_segm_start(seg), idc.get_segm_end(seg))
        self.log(2, 'Tagged pointer conversion complete')

    @staticmethod
    def _tagged_pointer_tag(tp):
        return (tp >> 48) & 0xffff

    @staticmethod
    def _tagged_pointer_untag(tp):
        return tp | 0xffff000000000000

    @staticmethod
    def _tagged_pointer_link(tag):
        return (tag >> 1) & ~0x3

    def _is_tagged_pointer_format(self, value):
        return self._tagged_pointer_tag(value) != 0xffff and (value & 0x0000ffff00000000) == 0x0000fff000000000

    def _is_tagged_pointer(self, value):
        return self._is_tagged_pointer_format(value) and idau.is_mapped(self._tagged_pointer_untag(value), value=False)

    def _tagged_pointer_next(self, ea, tp, end=None):
        assert ea
        # First try to get the offset to the next link.
        if tp:
            link_offset = self._tagged_pointer_link(self._tagged_pointer_tag(tp))
            if link_offset:
                return ea + link_offset
            # Skip the current tagged pointer in preparation for scanning.
            ea += idau.WORD_SIZE
        # We don't have a link. Do a forward scan until we find the next tagged pointer.
        self.log(3, 'Scanning for next tagged pointer')
        if end is None:
            end = idc.get_segm_end(ea)
        for value, value_ea in idau.ReadWords(ea, end, step=4, addresses=True):
            if self._is_tagged_pointer(value):
                return value_ea
        # If we didn't find any tagged pointers at all, return None.
        return None

    def _untag_pointer(self, ea, tp):
        self.log(4, 'Untagging pointer at {:x}', ea)
        idau.patch_word(ea, self._tagged_pointer_untag(tp))
        idc.op_plain_offset(ea, 0, 0)

    def _untag_pointers_in_range(self, start, end):
        ea, tp = start, None
        while True:
            ea = self._tagged_pointer_next(ea, tp, end)
            if ea is None or ea >= end:
                break
            tp = idau.read_word(ea)
            if not self._is_tagged_pointer(tp):
                self.log(1, 'Tagged pointer traversal failed: ea={:x}, tp={:x}'.format(ea, tp))
                break
            self._untag_pointer(ea, tp)

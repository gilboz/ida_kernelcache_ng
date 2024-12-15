import plistlib
from typing import List

import ida_auto
import idaapi
import idautils
import idc

from ida_kernelcache import (
    ida_utilities as idau,
    kplist,
)
from ida_kernelcache.consts import KCFormat
from ida_kernelcache.exceptions import PhaseException
from ida_kernelcache.phases import *

_log = idau.make_log(0, __name__)



class KernelCache(object):

    def __init__(self):
        super().__init__()
        self._base = None
        self._prelink_info = None
        self.format = KCFormat.MERGED_12

        # TODO: type annotations!
        self.classes = {}  # A global map from class names to ClassInfo objects. See collect_class_info().
        self.vtables = {}  # A global map from the address each virtual method tables in the kernelcache to its length.

        # Once upon a time every KEXT had it's GOT ...
        if any(idc.get_segm_name(seg).endswith("__got") for seg in idautils.Segments()):
            self.format = KCFormat.NORMAL_11

    @property
    def base(self):
        """
        Find the kernel base address (the address of the main kernel Mach-O header).
        """
        if self._base is None:
            base = idaapi.get_fileregion_ea(0)
            if base != 0xffffffffffffffff:
                return base
            seg = [seg for seg in map(idaapi.get_segm_by_name, ['__TEXT.HEADER', '__TEXT:HEADER']) if seg]
            if not seg:
                raise RuntimeError("unable to find kernel base")
            self._base = seg[0].start_ea

        return self._base

    @staticmethod
    def _find_prelink_info_segments():
        """Find all candidate __PRELINK_INFO segments (or sections).

        We try to identify any IDA segments with __PRELINK_INFO in the name so that this function will
        work both before and after automatic rename. A more reliable method would be parsing the
        Mach-O.
        """
        segments = []
        # Gather a list of all the possible segments.
        for seg in idautils.Segments():
            name = idc.get_segm_name(seg)
            if '__PRELINK_INFO' in name or name == '__info':
                segments.append(seg)
        if len(segments) < 1:
            _log(0, 'Could not find any __PRELINK_INFO segment candidates')
        elif len(segments) > 1:
            _log(1, 'Multiple segment names contain __PRELINK_INFO: {}', [idc.get_segm_name(seg) for seg in segments])
        return segments

    @property
    def prelink_info(self):
        """
        Find and parse the kernel __PRELINK_INFO dictionary.
        """
        if self._prelink_info is None:

            segments = self._find_prelink_info_segments()

            for segment in segments:
                seg_start = idc.get_segm_start(segment)
                seg_end = idc.get_segm_end(segment)

                # prelink_info_string = idc.get_strlit_contents(segment)
                prelink_info_string = idc.get_bytes(seg_start, seg_end - seg_start)
                if prelink_info_string != None:
                    if prelink_info_string[:5] == b"<dict":
                        prelink_info_string = prelink_info_string.replace(b"\x00", b"")
                        prelink_info_string = prelink_info_string.decode()
                        self._prelink_info = kplist.kplist_parse(prelink_info_string)
                    elif prelink_info_string.startswith(b"<?xml version=\"1.0\""):
                        self._prelink_info = plistlib.loads((prelink_info_string.rstrip(b"\x00")))

            # Still None?
            if self._prelink_info is None:
                _log(0, 'Could not find __PRELINK_INFO')
        return self._prelink_info

    @staticmethod
    def _check_filetype():
        filetype = idaapi.get_file_type_name()
        """Checks that the filetype is compatible before trying to process it."""
        return ('Mach-O' in filetype or 'kernelcache' in filetype) and 'ARM64' in filetype

    def all_phases(self):
        phases = []
        if self.format == KCFormat.MERGED_12 and idaapi.IDA_SDK_VERSION < 720:
            phases.append(TaggedPointers)

        phases += [
            RenameSegments,
            CollectClasses,
            CollectVtables,
            AddVtableSymbols,
            AddMetaClassSymbols
        ]

        return phases
        # # TODO: Not relevant in iOS 12 and above..
        # print('Initializing data offsets')
        # offset.initialize_data_offsets()
        #
        # # TODO: depends on collect_vtables.py
        # print('Initializing vtables')
        # vtable.initialize_vtables()
        #
        # # TODO: depends on collect_vtables.py
        # print('Initializing vtable symbols')
        # vtable.initialize_vtable_symbols()
        #
        # # TODO: depends on collect_metaclass.py
        # print('Initializing metaclass symbols')
        # metaclass.initialize_metaclass_symbols()
        #
        # # if self.format == KCFormat.NORMAL_11:
        # #     print('Initializing offset symbols')
        # #     offset.initialize_offset_symbols()
        # #
        # #     print('Initializing stub symbols')
        # #     stub.
        # #     initialize_stub_symbols()
        #
        # # TODO: depends on collect_vtables.py
        # print('Initializing vtable method symbols')
        # vtable.initialize_vtable_method_symbols()
        #
        # # TODO: depends on collect_vtable.py and collect_classes.pyki
        # print('Initializing vtable structs')
        # class_struct.initialize_vtable_structs()
        #
        # # TODO: depends on collect_vtable.py and collect_classes.py
        # print('Initializing class structs')
        # class_struct.initialize_class_structs()

    def process(self, phases: List = None):
        """
        Process the kernelcache in IDA for the first time.

         This function performs all the standard processing available in this module:
             * Convert iOS 12's new static tagged pointers into normal kernel pointers.
             * Parse the kernel's `__PRELINK_INFO.__info` section into a dictionary.
             * Renames segments in IDA according to the names from the __PRELINK_INFO dictionary (split
               kext format kernelcaches only).
             * Converts pointers in data segments into offsets.
             * Locates virtual method tables, converts them to offsets, and adds vtable symbols.
             * Locates OSMetaClass instances for top-level classes and adds OSMetaClass symbols.
             * Symbolicates offsets in `__got` sections and stub functions in `__stubs` sections.
             * Symbolicates methods in vtables based on the method names in superclasses.
             * Creates IDA structs representing the C++ classes in the kernel.
         """
        if not self._check_filetype():
            _log(-1, f'Unsupported file type! This script supports ARM64 kernelcaches only!"')
            return

        # Run all phases
        for phase_cls in phases:
            phase = phase_cls(self)

            try:
                phase.run()
            except PhaseException as ex:
                if True:
                    _log(-1, ex)
                raise

            # auto-analyze after every phase
            ida_auto.auto_wait()

import plistlib
import re

import ida_auto
import ida_segment
import idaapi
import idc
import logging
from ida_kernelcache import (
    kplist, rtti_info, consts,
)
from ida_kernelcache.exceptions import PhaseException
from ida_kernelcache.phases import ALL_PHASES
from ida_kernelcache.ida_helpers.abstractions import Segment

logging.basicConfig(format='%(levelname)-10s %(name)s: %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)


class KernelCache(object):
    """
    I have the assumption that we are always interested in the latest kernelcaches. There isn't much sense in putting
    effort to support old iOS releases. Hopefully we can be satisfied with just supporting that latest iOS major.
    This will not attempt to have any backwards compatibility.
    As long as this project is maintained, Hopefully this class will remain up to date with iOS ker

    Current kernelcaches are delivered as a Mach-O FILESET. IDA 9.0 seems to handle the LC_FILESET_ENTRY load command
    well enough, and it also parses inner Mach-O header of each Kext.
    The current kernelcache I'm working on has 311 kexts and after loading it into IDA we get a total of *4301* segments
    """

    def __init__(self):
        super().__init__()
        self._base = None
        self._prelink_info = None

        # TODO: make this persistent?
        self.class_info_map = rtti_info.ClassInfoMap()

        self.segments_list: list[Segment] = []

        for i in range(ida_segment.get_segm_qty()):
            swig_segment = ida_segment.getnseg(i)
            self.segments_list.append(Segment(swig_segment))

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

    @property
    def prelink_info(self):
        """
        Find and parse the kernel __PRELINK_INFO dictionary.
        """
        if self._prelink_info is None:

            # Find all candidate __PRELINK_INFO segments (or sections).
            # We try to identify any IDA segments with __PRELINK_INFO in the name so that this function will
            # work both before and after automatic rename. A more reliable method would be parsing the Mach-O.
            try:
                prelink_segment = next(s for s in self.segments_list if '__PRELINK_INFO' in s.name)
            except StopIteration:
                log.error('Could not find any __PRELINK_INFO segment candidates')
                return None

            prelink_info_string = idc.get_bytes(prelink_segment.start_ea, prelink_segment.size)
            if prelink_info_string != None:
                if prelink_info_string[:5] == b"<dict":
                    prelink_info_string = prelink_info_string.replace(b"\x00", b"")
                    prelink_info_string = prelink_info_string.decode()
                    self._prelink_info = kplist.kplist_parse(prelink_info_string)
                elif prelink_info_string.startswith(b"<?xml version=\"1.0\""):
                    self._prelink_info = plistlib.loads((prelink_info_string.rstrip(b"\x00")))

            if self._prelink_info is None:
                log.error('Failed to parse __PRELINK_INFO')

        return self._prelink_info

    def segments_matching(self, pattern: str) -> tuple[Segment, None, None]:
        for s in self.segments_list:
            if re.match(pattern, s.name, flags=re.IGNORECASE):
                yield s

    def all_kexts(self) -> list[str]:
        if not self.prelink_info:
            return []
        return [k['CFBundleIdentifier'] for k in self.prelink_info['_PrelinkInfoDictionary']]

    @staticmethod
    def is_supported() -> bool:
        """
        Checks that the filetype is compatible before trying to process it.

        """

        if idaapi.IDA_SDK_VERSION < consts.MIN_IDA_SDK_VERSION:
            log.error('Unsupported IDA version. The minimum requirement is to run IDA 9.0!')
            return False

        filetype = idaapi.get_file_type_name()
        if ('Mach-O' not in filetype and 'kernelcache' not in filetype) or 'ARM64' not in filetype:
            log.error(f'Unsupported file type! This script supports ARM64 kernelcaches only!"')
            return False
        return True

    def process(self, phases: list | None = None):
        """
        TODO: edit this docstring
        Process the kernelcache in IDA for the first time.

         This function performs all the standard processing available in this module:
             * Converts pointers in data segments into offsets.
             * Locates virtual method tables, converts them to offsets, and adds vtable symbols.
             * Locates OSMetaClass instances for top-level classes and adds OSMetaClass symbols.
             * Symbolicates offsets in `__got` sections and stub functions in `__stubs` sections.
             * Symbolicates methods in vtables based on the method names in superclasses.
             * Creates IDA structs representing the C++ classes in the kernel.
         """
        if not self.is_supported():
            return

        log.info('processing kernelcache..')
        if not phases:
            phases = ALL_PHASES

        # Run all phases
        for phase_cls in phases:
            log.info(f'***** Starting phase: {phase_cls.__name__} *****')
            phase = phase_cls(self)

            try:
                phase.run()
            except PhaseException as ex:
                if True:
                    log.exception(ex)
                raise
            else:
                log.info(f'***** Finished phase: {phase_cls.__name__} *****')

            # Wait for auto analysis to complete after every phase.
            # Honestly I'm not sure if this is needed but the auto analyzer is IDLE it will return immediately
            ida_auto.auto_wait()
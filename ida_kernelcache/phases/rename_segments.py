"""
ida_kernelcache/rename_segments.py
Brandon Azad

Renaming segments of the kernelcache binary in IDA, using information from the prelink info
No prior initialization is necessary.
"""

import re
import idc
from ida_segment import SEGPERM_READ, SEGPERM_WRITE, SEGPERM_EXEC
from ida_kernelcache import ida_utilities as idau
from .base_phase import BasePhase

idc.import_type(-1, 'mach_header_64')
idc.import_type(-1, 'load_command')
idc.import_type(-1, 'segment_command_64')
idc.import_type(-1, 'section_64')

_LC_SEGMENT_64 = 0x19


class RenameSegments(BasePhase):
    """
    Rename the kernelcache segments in IDA according to the __PRELINK_INFO data.

    Rename the kernelcache segments based on the contents of the __PRELINK_INFO dictionary.
    Segments are renamed according to the scheme '[<kext>:]<segment>.<section>', where '<kext>' is
    the bundle identifier if the segment is part of a kernel extension. The special region
    containing the Mach-O header is renamed '[<kext>:]<segment>.HEADER'.
    """
    KERNEL_SKIP = ['__PRELINK_TEXT', '__PLK_TEXT_EXEC', '__PRELINK_DATA', '__PLK_DATA_CONST']

    def run(self):
        # First fix kernel segments permissions
        self.log(1, 'Fixing kernel segments permissions')
        self._fix_kernel_segments()

        # Rename the kernel segments.
        self.log(1, 'Renaming kernel segments')
        self._initialize_segments_in_kext(None, self._kc.base, skip=self.KERNEL_SKIP)

        # Process each kext identified by the __PRELINK_INFO. In the new kernelcache format 12-merged,
        # the _PrelinkExecutableLoadAddr key is missing for all kexts, so no extra segment renaming
        # takes place.
        prelink_info_dicts = self._kc.prelink_info['_PrelinkInfoDictionary']
        for kext_prelink_info in prelink_info_dicts:
            kext = kext_prelink_info.get('CFBundleIdentifier', None)
            mach_header = kext_prelink_info.get('_PrelinkExecutableLoadAddr', None)

            if kext is not None and mach_header is not None:
                orig_kext = idc.get_segm_name(mach_header).split(':', 1)[0]

                # TODO: check if mach_header is valid
                if not orig_kext:
                    continue

                if '.kpi.' not in kext and orig_kext != kext:
                    self.log(0, 'Renaming kext {} -> {}', orig_kext, kext)

                self.log(1, 'Renaming segments in {}', kext)
                self._initialize_segments_in_kext(kext, mach_header)

    @staticmethod
    def _segments():
        seg_ea = idc.get_first_seg()
        while seg_ea != idc.BADADDR:
            name = idc.get_segm_name(seg_ea)
            yield seg_ea, name
            seg_ea = idc.get_next_seg(seg_ea)

    def _fix_kernel_segments(self):
        for seg_off, seg_name in self._segments():
            perms = None
            seg_name = seg_name.strip()

            if re.match(r".*[_.](got|const|cstring)$", seg_name, re.I):
                self.log(1, "rw " + seg_name)
                perms = SEGPERM_READ | SEGPERM_WRITE
            elif re.match(r".*[_.](text|func|stubs)$", seg_name, re.I):
                self.log(1, "rx " + seg_name)
                perms = SEGPERM_READ | SEGPERM_EXEC
            elif re.match(r".*[_.](data)$", seg_name, re.I):
                self.log(1, "rw " + seg_name)
                perms = SEGPERM_READ | SEGPERM_WRITE

            if perms is not None:
                idc.set_segm_attr(seg_off, idc.SEGATTR_PERM, perms)

    def _initialize_segments_in_kext(self, kext, mach_header, skip=[]):
        """
        Rename the segments in the specified kext.
        """

        def log_seg(segname, segstart, segend):
            self.log(3, '+ segment {: <20} {:x} - {:x}  ({:x})', segname, segstart, segend,
                     segend - segstart)

        def log_sect(sectname, sectstart, sectend):
            self.log(3, '  section {: <20} {:x} - {:x}  ({:x})', sectname, sectstart, sectend,
                     sectend - sectstart)

        def log_gap(gapno, start, end, mapped):
            mapped = 'mapped' if mapped else 'unmapped'
            self.log(3, '  gap     {: <20} {:x} - {:x}  ({:x}, {})', gapno, start, end,
                     end - start, mapped)

        def process_region(segname, name, start, end):
            assert end >= start
            if segname in skip:
                self.log(2, 'Skipping segment {}', segname)
                return
            newname = '{}.{}'.format(segname, name)
            if kext:
                newname = '{}:{}'.format(kext, newname)
            if start == end:
                self.log(2, 'Skipping empty region {} at {:x}', newname, start)
                return
            ida_segstart = idc.get_segm_start(start)
            if ida_segstart == idc.BADADDR:
                self.log(0, "IDA doesn't think this is a real segment: {:x} - {:x}", start, end)
                return
            ida_segend = idc.get_segm_end(ida_segstart)
            if start != ida_segstart or end != ida_segend:
                self.log(0, 'IDA thinks segment {} {:x} - {:x} should be {:x} - {:x}', newname, start, end,
                         ida_segstart, ida_segend)
                return
            self.log(2, 'Rename {:x} - {:x}: {} -> {}', start, end, idc.get_segm_name(start), newname)
            idc.set_segm_name(start, newname)

        def process_gap(segname, gapno, start, end):
            mapped = idau.is_mapped(start)
            log_gap(gapno, start, end, mapped)
            if mapped:
                name = 'HEADER' if start == mach_header else '__gap_' + str(gapno)
                process_region(segname, name, start, end)

        def _macho_segments_and_sections(ea):
            """
            A generator to iterate through a Mach-O file's segments and sections.

            Each iteration yields a tuple:
                (segname, segstart, segend, [(sectname, sectstart, sectend), ...])
            """

            def _convert_list_to_bytes(l):
                return bytes(l) if isinstance(l, list) else l

            # TODO: is this really needed in new IDA versions..?
            hdr = idau.read_struct(ea, 'mach_header_64', asobject=True)
            nlc = hdr.ncmds
            lc = int(hdr) + len(hdr)
            lcend = lc + hdr.sizeofcmds
            while lc < lcend and nlc > 0:
                loadcmd = idau.read_struct(lc, 'load_command', asobject=True)
                if loadcmd.cmd == _LC_SEGMENT_64:
                    segcmd = idau.read_struct(lc, 'segment_command_64', asobject=True)
                    segname = idau.null_terminated(_convert_list_to_bytes(segcmd.segname))
                    segstart = segcmd.vmaddr
                    segend = segstart + segcmd.vmsize
                    sects = []
                    sc = int(segcmd) + len(segcmd)
                    for i in range(segcmd.nsects):
                        sect = idau.read_struct(sc, 'section_64', asobject=True)
                        sectname = idau.null_terminated(_convert_list_to_bytes(sect.sectname))
                        sectstart = sect.addr
                        sectend = sectstart + sect.size
                        sects.append((sectname, sectstart, sectend))
                        sc += len(sect)
                    yield (segname, segstart, segend, sects)
                lc += loadcmd.cmdsize
                nlc -= 1

        for segname, segstart, segend, sects in _macho_segments_and_sections(mach_header):
            log_seg(segname, segstart, segend)
            lastend = segstart
            gapno = 0
            for sectname, sectstart, sectend in sects:
                if lastend < sectstart:
                    process_gap(segname, gapno, lastend, sectstart)
                    gapno += 1
                log_sect(sectname, sectstart, sectend)
                process_region(segname, sectname, sectstart, sectend)
                lastend = sectend
            if lastend < segend:
                process_gap(segname, gapno, lastend, segend)
                gapno += 1

import ida_hexrays
import ida_ua
import ida_xref
import idaapi
import idautils
import idc

from ida_kernelcache import consts, rtti
from ida_kernelcache.exceptions import PhaseException, NewEdgeCaseError
from ida_kernelcache.ida_helpers import decompiler, generators, functions, names, strings
from .base_phase import BasePhase


class CollectVtables(BasePhase):
    """
    This phase depends on the CollectClasses phase and must run after it
    """
    GET_METACLASS_FUNC_SIZE = 16
    SENTINEL_MASK = 0xffffffffffff0000

    def __init__(self, kc):
        super().__init__(kc)

        # Track metaclass ea that we could not find the ::getMetaClass
        self._associated_vtables: set[int] = set()
        self._not_found_set: set[int] = set()
        self._not_functions_set: set[int] = set()
        self._metaclass_ea_to_getmetaclass_ea: dict[int, int] = {}
        self.X0_REGISTER_INDEX = idautils.GetRegisterList().index('X0')

    def run(self):
        if not self._kc.class_info_map:
            raise PhaseException(f"There are no entries in the KernelCache.classes dictionary.. consider running CollectClasses phase before {self.__class__}")

        self._handle_pure_virtual()
        self._collect_getmetaclass_methods()
        self._collect_vtables_new()

        for vmethod_ea in self._not_functions_set:
            # TODO: resolve this!
            self.log.debug(f'The function boundaries of the vmethod at {vmethod_ea:#x} are wrong and I could not fix it automatically!')
        self.log.warning(f'There are {len(self._not_functions_set)} virtual methods with wrong function boundaries')

    def _handle_pure_virtual(self):
        str_ea = strings.find_str(consts.CXA_PURE_VIRTUAL).ea
        candidate = ida_xref.get_first_dref_to(str_ea)
        if candidate == idc.BADADDR:
            raise PhaseException(f'Could not find {consts.CXA_PURE_VIRTUAL} string reference!')

        if ida_xref.get_next_dref_to(str_ea, candidate) != idc.BADADDR:
            raise PhaseException(f'{consts.CXA_PURE_VIRTUAL} string has more than 1 xref!')

        cxa_pure_virtual_ea = functions.get_func_start(candidate)
        self.log.info(f'Found {consts.CXA_PURE_VIRTUAL} at {cxa_pure_virtual_ea:#x}')
        new_func_name = f'_{consts.CXA_PURE_VIRTUAL}'

        if not names.set_ea_name(cxa_pure_virtual_ea, new_func_name):
            self.log.error(f'Failed to change the function name at {cxa_pure_virtual_ea:#x} to {new_func_name}')

        # Store this information in the VtableInfo class, this will be used when constructing the VtableEntry instances
        rtti.VtableInfo.CXA_PURE_VIRTUAL_EA = cxa_pure_virtual_ea

    def _collect_getmetaclass_methods(self) -> None:
        """
        We go over all the classes that we found so far, and search their corresponding ::getMetaClass() method
        """
        num_fallback_findings = 0
        self.log.info('Searching for ::getMetaClass methods..')

        for metaclass_ea, class_info in self._kc.class_info_map.items_by_type(key_type=int):
            candidates = set()
            for xref_ea in idautils.DataRefsTo(metaclass_ea):
                xref_func = idaapi.get_func(xref_ea)

                # Skip xrefs that are not part of a function or are too big to be valid candidates
                if xref_func is None:
                    continue

                potential_func_start = idaapi.prev_head(xref_ea, 0)
                # Prefer to use ctree inspection to determine this
                if xref_func.start_ea == potential_func_start and xref_func.size() == self.GET_METACLASS_FUNC_SIZE:
                    if self._is_getmetaclass_method(xref_ea, metaclass_ea):
                        candidates.add(xref_func.start_ea)
                        continue

                # When IDA messes up the initial auto-analysis we have to resort to the dissasembly
                if self._is_getmetaclass_method_fallback(potential_func_start, metaclass_ea):
                    num_fallback_findings += 1
                    candidates.add(potential_func_start)

            if len(candidates) == 1:
                self._metaclass_ea_to_getmetaclass_ea[metaclass_ea] = candidates.pop()
                self.log.debug(f'Found {class_info.class_name}::getMetaClass at {self._metaclass_ea_to_getmetaclass_ea[metaclass_ea]:#x} metaclass_ea {metaclass_ea:#x}')
            elif len(candidates) > 1:
                raise PhaseException(f'Found multiple candidates for {class_info.class_name}::getMetaClass! {", ".join(f"{x:#x}" for x in candidates)}')
            else:
                self._not_found_set.add(metaclass_ea)

        # There are a small amount of classes which seems like we cannot associate them with a vtable (simply because it doesn't exist in the binary..?)
        # I'm not sure when the compiler decides not to yield vtables in the binary,
        # I guess this is some sort of optimization where an intermediate class (in the inheritance tree) does not override and method.
        for metaclass_ea in self._not_found_set:
            class_info = self._kc.class_info_map[metaclass_ea]

            # TODO: Probably a better check is to see if all of the references to this metaclass_ea is in __mod_init or __mod_term.
            if class_info.is_middleclass():
                class_info.optimized = True
                self.log.info(f'Marked {class_info.class_name} metaclass_ea:{metaclass_ea:#x} as optimized without a vtable')
            else:
                raise PhaseException(f'Failed to find {class_info.class_name}::getMetaClass! metaclass_ea {metaclass_ea:#x}')

        # Log statistics to the user
        self.log.info(f'Found {len(self._metaclass_ea_to_getmetaclass_ea)}/{len(self._kc.class_info_map)}! '
                      f'fallback: {num_fallback_findings} not found: {len(self._not_found_set)}')

    def _is_getmetaclass_method(self, xref_ea: int, metaclass_ea: int) -> bool:
        cfunc = ida_hexrays.decompile(xref_ea)
        if cfunc is None:
            raise PhaseException(f'hexrays decompilation failed! ea:{xref_ea:#x}')

        root: ida_hexrays.cinsn_t = cfunc.body

        if root.op == ida_hexrays.cit_block and len(root.cblock) == 1 and root.cblock[0].op == ida_hexrays.cit_return:
            return_statement: ida_hexrays.creturn_t = root.cblock[0].creturn
            expr = decompiler.traverse_casts_or_ref_branch(return_statement.expr)
            return expr.op == ida_hexrays.cot_obj and expr.obj_ea == metaclass_ea

    def _is_getmetaclass_method_fallback(self, potential_func_start: int, metaclass_ea: int) -> bool:
        """
        In practice the fallback is only used when IDA auto-analysis fails, which happens from time to time when Apple release kernelcaches
        that contain new instructions that are not yet supported by the ARM64 disassembler in IDA.

        Every ::getMetaClass method should look the following set of instructions
        BTI c
        ADRL X0, metaclass_ea
        RET
        """
        mnemonics = [
            'BTI',
            'ADRL',
            'RET'
        ]

        for mnem, insn in zip(mnemonics, generators.Instructions(potential_func_start, count=3)):
            insn: ida_ua.insn_t
            if mnem != insn.get_canon_mnem():
                return False

            match mnem:
                case 'BTI':
                    if insn.Op1.value != 0x63:  # 'c'
                        return False

                case 'ADRL':
                    if insn.Op1.reg != self.X0_REGISTER_INDEX or insn.Op2.value != metaclass_ea:
                        return False
        return True

    def _collect_vtables_new(self):
        """
        To collect the vtables we iterate of the ClassInfo objects top down using BFS.
        Every ::getMetaClass() method should have a single data reference in a const segment
        """
        num_with_sentinel = 0

        for class_info in self._kc.class_info_map.bfs(must_have_vtable=False):

            # Skip optimized classes that have no vtable
            if class_info.optimized:
                continue

            if class_info.class_name == 'OSMetaClass':
                # TODO: OSMetaClass::getMetaClass is referenced in all of the other MetaClasses
                self.log.warning('Currently not collecting *::MetaClass vtables (needs to be implemented)')
                continue

            getmetaclass_ea = self._metaclass_ea_to_getmetaclass_ea[class_info.metaclass_ea]
            candidates = list(generators.DataRefsToWithSegmentFilter(getmetaclass_ea, r'.*__const$'))

            # Look for the vtable that references this method!
            if len(candidates) == 1:
                vtable_ea = candidates[0] - consts.VTABLE_GETMETACLASS_OFFSET
                if vtable_ea in self._associated_vtables:
                    raise PhaseException(f'Vtable {vtable_ea:#x} is already associated with some other class!')
                else:
                    self._associated_vtables.add(vtable_ea)

                # Count the number of methods in this vtable to determine its length
                num_vtable_methods = consts.INITIAL_NUM_VTABLE_METHODS
                has_sentinel = False

                for vmethod_ea in generators.ReadWords(candidates[0], idc.get_segm_end(vtable_ea)):
                    # Stop on the first NULL
                    if not vmethod_ea:
                        break

                    if vmethod_ea & self.SENTINEL_MASK == self.SENTINEL_MASK:
                        # TODO: is this virtual inheritance? If so, how do we parse it?
                        num_with_sentinel += 1
                        self.log.debug(f'{vtable_ea:#x} vtable for {class_info.class_name:50s} Found sentinel! {vmethod_ea:#x}')
                        has_sentinel = True
                        break

                    # If this happens this is probably because IDA auto-analysis failed to determine function boundaries correctly
                    if functions.get_func_start(vmethod_ea, raise_error=False) != vmethod_ea:
                        # TODO: Rework the force function implementation
                        if functions.force_function(vmethod_ea):
                            self.log.debug(f'Fixed function boundaries at {vmethod_ea:#x}')
                        else:
                            # TODO: solve this by fixing the __noreturn attribute missing from panic functions upon initial analysis
                            self._not_functions_set.add(vmethod_ea)

                    num_vtable_methods += 1

                vtable_end_ea = vtable_ea + num_vtable_methods * consts.WORD_SIZE + consts.VTABLE_FIRST_METHOD_OFFSET
                self.log.debug(f'Found vtable of {class_info.class_name} {vtable_ea:#x}-{vtable_end_ea:#x} num methods:{num_vtable_methods}')

                vtable_info = rtti.VtableInfo(vtable_ea, vtable_end_ea, has_sentinel)
                class_info.vtable_info = vtable_info
                vtable_info.class_info = class_info

                # Now we maintain the VMethodsInfoMap which is a central storage that contains a unique instance of VMethodInfo for every vmethod_ea we encounter.
                # It is important to have unique references to vmethods because on later phases, We process the vtable entries for symbolication.
                # We can encounter the same vmethod in multiple vtable entries and want to have a single source of truth that holds the information that is specific to the vmethod,  e.g. the symbol for that vmethod.
                # For every vmethod_ea we encounter for the first time a new VMethodInfo instance is created.
                # Every VMethodInfo object is associated with the VtableEntry object that contains it and vice versa.
                # Ideally, we would be able to this while constructing the VtableEntry objects in inside the VtableInfo class.
                # However, the entries of a VtableInfo instance are built lazily, upon first access, (and cached in an internal list).
                # Modifying the VMethodsInfo map from that context would require passing a reference to the RTTIDatabase or storing it as global which both are a worse design in my opinion.
                for vtable_entry in vtable_info.entries:
                    self._kc.vmethod_info_map.add_relation(vtable_entry)
            elif len(candidates) > 1:
                # TODO: understand why AppleBasebandPCIMessageQueueBase behaves this way and remove it from the blacklist
                # This currently only happens for one class: AppleBasebandPCIMessageQueueBase
                # Its behaviour is very different from all the other classes in the kernelcache because it seems like there are really 4 different vtable types in the kernelcache
                if class_info.class_name != 'AppleBasebandPCIMessageQueueBase':
                    candidates_str = ', '.join(hex(x) for x in candidates)
                    self.log.warning(f'{class_info.class_name} {getmetaclass_ea:#x} has multiple vtable candidates {candidates_str}')
                    raise NewEdgeCaseError(f'{class_info.class_name} new edge-case discovered')
            else:
                raise PhaseException(f'No potential vtable xref to {class_info.class_name}::getMetaClass found!')

        if num_with_sentinel:
            self.log.warning(f'{num_with_sentinel} classes are possibly subject to multiple inheritance, which we do not support yet!')


# TODO: fix the force_function functionality either in this phase or an indepenedent phase
# def _convert_vtable_methods_to_functions(vtable, length):
#     """Convert each virtual method in the vtable into an IDA function."""
#     for vmethod in vtable_methods(vtable, length=length):
#         if not idau.force_function(vmethod):
#             _log(0, 'Could not convert virtual method {:#x} into a function', vmethod)


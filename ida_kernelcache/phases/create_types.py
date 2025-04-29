"""
Refer to: https://docs.hex-rays.com/user-guide/user-interface/menu-bar/view/c++-type-details
This is why I set the EA as struct member comments: https://hex-rays.com/blog/igor-tip-of-the-week-15-comments-in-structures-and-enums
"""
import ida_kernwin
import ida_typeinf

from ida_kernelcache import consts, symbols
from ida_kernelcache.exceptions import PhaseException
from ida_kernelcache.ida_helpers import types
from .base_phase import BasePhase


class CreateTypes(BasePhase):
    """
    Using the classes and vtables data from previous phases, the CreateTypes phase will define local types in the IDB.
    The struct definitions should represent the inheritance relationship between the classes
    This phase was improved to support the c++ objects support that was added in IDA 7.2, in particular the __cppobj
    attribute and the special _vtbl_layout suffix.

    In IDA a cpp structure has the TAUDT_CPPOBJ flag set in its udt_type_data_t object.
    Inheritance is achieved through a special member which is udm_t that is marked as baseclass at offset 0
    """
    DEFAULT_OVERRIDE_CHOICE = 1

    def __init__(self, kc):
        super().__init__(kc)

    def run(self):
        # This check will raise an exception in case we cannot continue because there are conflicts
        self._check_for_conflicts()
        self._create_types_bfs()

    def _check_for_conflicts(self):
        num_conflicts = 0
        for _, class_name in self._kc.class_info_map.keys():
            if types.does_type_exist(class_name):
                self.log.debug(f'{class_name} already exists!')
                num_conflicts += 1

        if num_conflicts:
            if not ida_kernwin.ask_yn(self.DEFAULT_OVERRIDE_CHOICE,
                                      f'{num_conflicts}/{len(self._kc.class_info_map)} types already exist! Continue by overriding them?'):
                raise PhaseException(f'User did not allow to override existing type information! '
                                     f'There are {num_conflicts} existing types')

    def _create_types_bfs(self):
        """
        Do a breadth first scan, the inheritance relationship forms a directed acylic graph so there is no need
        to track down visited nodes
        """
        num_vtbl_types = 0
        num_created = 0
        func_name_conflicts = 0
        for class_info in self._kc.class_info_map.bfs(must_have_vtable=False):

            # TODO: stop skipping OSMetaClass when we fix its vtable finding implementation
            if class_info.class_name == 'OSMetaClass':
                continue

            if class_info.class_size % consts.WORD_SIZE:
                raise PhaseException(f'{class_info.class_name} size not aligned to {consts.WORD_SIZE}')

            field_decls, func_decls = [], []
            if class_info.is_subclass():
                superclass_name = f': {class_info.superclass.class_name}'
            else:
                field_decls.append(consts.VPTR_FIELD)
                superclass_name = ''

            for offset in class_info.data_field_offsets():
                field_decls.append(consts.DATA_FIELD_TEMPLATE.format(offset=offset))

            cls_type_decl = consts.CPPOBJ_DECL_TEMPLATE.format(
                metaclass_ea=class_info.metaclass_ea,
                class_name=class_info.class_name,
                superclass_name=superclass_name,
                data_fields=consts.FIELD_SEP.join(field_decls)
            )

            num_created += 1

            # Skip creation of vtable types for optimized classes (without vtables)
            if class_info.optimized:
                types.create_type_from_decl(f'{cls_type_decl}', replace=True)
                class_local_type = types.LocalType(class_info.class_name)
                self.log.info(f'{class_info.class_name} is an optimized class without a vtable! Class type ordinal: {class_local_type.ordinal}')
                continue

            func_names: set[str] = set()

            # We do not create a vtable type for
            for vtable_entry in class_info.vtable_info.entries:

                # TODO: Even though vtable entries might be pure virtual they still have a different pac diversifier
                #  and we can figure out what the name of the vtable entry should be
                func_name = consts.VMETHOD_NAME_TEMPLATE.format(index=vtable_entry.index)

                if not vtable_entry.pure_virtual and vtable_entry.vmethod_info.mangled_symbol:
                    # Might raise StringExtractionError or DemanglingError
                    func_name = symbols.extract_method_name(vtable_entry.vmethod_info.mangled_symbol)

                # TODO: IDA has a bug that does will fail to parse vtable declaration if two vmethods have the same name,
                #  even if they have a different signature.
                if func_name in func_names:
                    func_name_conflicts += 1

                    # TODO: maybe just add a running suffix
                    func_name = consts.VMETHOD_NAME_TEMPLATE.format(index=vtable_entry.index)

                func_names.add(func_name)

                # TODO: Implement a better function signature applying either though the mangled symbol or by using the decompiler's guessing
                func_decls.append(consts.VIRTUAL_FUNC_TEMPLATE.format(func_name=func_name,
                                                                      func_sig=f'{class_info.class_name} *__hidden this',
                                                                      vmethod_ea=vtable_entry.vmethod_ea))

            vtbl_type_decl = consts.VTABLE_DECL_TEMPLATE.format(
                vtable_ea=class_info.vtable_info.vtable_ea,
                class_name=class_info.class_name,
                virtual_funcs=consts.FIELD_SEP.join(func_decls),
            )

            types.create_type_from_decl(f'{cls_type_decl}\n{vtbl_type_decl}', replace=True)
            vtable_local_type = types.LocalType(f'{class_info.class_name}_vtbl')
            vtable_local_type.udt.set_vftable(True)
            ida_typeinf.set_vftable_ea(vtable_local_type.ordinal, class_info.vtable_info.vtable_ea)

            self.log.debug(f'Created vtable type for {class_info.class_name}! ordinal: {vtable_local_type.ordinal}')

            if not class_info.is_subclass():
                self.log.info(f'Changing __vftable type in {class_info.class_name}')
                class_local_type = types.LocalType(class_info.class_name)
                class_local_type.set_member_type(0, f'{class_info.class_name}_vtbl *')
            num_vtbl_types += 1

        self.log.info(f'{num_created} new class types created!')
        self.log.info(f'{num_vtbl_types} new vtable types created!')
        self.log.info(f'{func_name_conflicts} function name conflicts!')

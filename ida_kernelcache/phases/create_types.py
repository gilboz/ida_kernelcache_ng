"""
Refer to: https://docs.hex-rays.com/user-guide/user-interface/menu-bar/view/c++-type-details
"""

from collections import deque

import idc

from .base_phase import BasePhase
import ida_kernelcache.consts as consts
import ida_kernelcache.ida_helpers.types as types
import ida_kernwin

from typing import TYPE_CHECKING

from .. import utils
from ..exceptions import PhaseException

if TYPE_CHECKING:
    from ida_kernelcache.rtti_info import ClassInfo


class CreateTypes(BasePhase):
    """
    Using the classes and vtables data from previous phases, the CreateTypes phase will define local types in the IDB.
    The struct definitions should represent the inheritance relationship between the classes
    This phase was improved to support the c++ objects support that was added in IDA 7.2, in particular the __cppobj
    attribute and the special _vtbl_layout suffix.


    In IDA a cpp structure has the TAUDT_CPPOBJ flag set in its udt_type_data_t object.
    Inheritance is achieved through a special member which is udm_t that is marked as baseclass at offset 0

    TODO: implement jump to indirect call by adding a comment including the vfunc ea in struct members of _vtable structures
    """
    DEFAULT_OVERRIDE_CHOICE = 0

    def __init__(self, kc):
        super().__init__(kc)

    def run(self):
        # This check will raise an exception in case we cannot continue because there are conflicts
        self._check_for_conflicts()

    def _check_for_conflicts(self):
        num_conflicts = 0
        for _, class_name in self._kc.class_info_map.keys():
            if types.does_type_exist(class_name):
                self.log.warning(f'{class_name} already exists!')
                num_conflicts += 1

        if num_conflicts:
            if not ida_kernwin.ask_yn(self.DEFAULT_OVERRIDE_CHOICE,
                                      f'{num_conflicts}/{len(self._kc.class_info_map)} types already exist! Continue by overriding them?'):
                raise PhaseException(f'User did not allow to override existing type information! '
                                     f'There are {num_conflicts} existing types')

    def _create_types_bfs(self):
        queue: deque[ClassInfo] = deque((ci for ci in self._kc.class_info_map.values() if ci.superclass is None))

        # Do a breadth first scan, the inheritance relationship forms a directed acylic graph so there is no need
        # to track down visited nodes

        while queue:
            class_info = queue.popleft()

            # TODO: handle types with unresolved vtables somehow..?
            if class_info.vtable_ea == idc.BADADDR:
                self.log.warning(f'Not creating type for {class_info.class_name} and its {utils.iterlen(class_info.descendants())} descendants')

            if class_info.class_size % consts.WORD_SIZE:
                raise PhaseException(f'{class_info.class_name} size not aligned to {consts.WORD_SIZE}')

            # Find superclass name!
            superclass_name = ''
            if class_info.superclass:
                superclass_name = f': {class_info.superclass.class_name}'

            for i in range(class_info.vtable_num_methods):
                # TODO: implement get_ea_name and
                func_name = consts.FUNC_NAME_TEMPlATE.format(i=i)

                # TODO: Implement get function signatures
                consts.VIRTUAL_FUNC_TEMPLATE.format(func_name=func_name, func_sig='')

            type_decl = consts.CLASS_DECL_TEMPLATE.format(
                class_name=class_info.class_name,
                superclass_name=superclass_name,
            )
            self.log.info(type_decl)
            types.create_type_from_decl(type_decl)

        for subclass in class_info.subclasses:
            queue.append(subclass)

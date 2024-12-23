"""
ida_kernelcache/rtti_info.py
Author: Brandon Azad, gilboz

This module defines the ClassInfo, VtableInfo and ClassInfoMap classes.
These classes are responsible for sotring information about a C++ RTTI information in the kernelcache.

The ClassInfoMap is meant to hold all of this information in an easy to use and fast data structure.
It uses both metaclass_ea and classname as indexes to the ClassInfo instances that are created in the CollectClasses phase
"""
import logging
import dataclasses

import ida_bytes
import idc

from ida_kernelcache import consts, utils
from ida_kernelcache.exceptions import ClassHasVtableError, VtableHasClassError, PhaseException
from ida_kernelcache.ida_helpers import generators

log = logging.getLogger(__name__)

class ClassInfo(object):
    """
    Python class to store C++ class information from KernelCache.
    """

    def __init__(self, class_name: str, metaclass: int, class_size: int, superclass: 'ClassInfo' = None):
        self.class_name = class_name
        self.metaclass_ea = metaclass
        self.class_size = class_size

        self.superclass: 'ClassInfo | None' = superclass
        self._vtable_info: 'VtableInfo | None' = None
        self.subclasses = set()

    def __repr__(self):
        return f'<ClassInfo {self.class_name}, size:{self.class_size}, metaclass:{self.metaclass_ea:#x}>'

    @property
    def vtable_info(self) -> 'VtableInfo | None':
        return self._vtable_info

    @vtable_info.setter
    def vtable_info(self, vtable_info: 'VtableInfo'):
        if self._vtable_info:
            raise ClassHasVtableError(f'{self.class_name} is already associated with vtable at {self._vtable_info.vtable_ea:#x}')
        self._vtable_info = vtable_info

    def is_subclass(self) -> bool:
        return self.superclass is not None

    def data_field_offsets(self) -> (int, None, None):
        """
        A generator that yields the offsets of every data field that is specific to this class.

        For example consider the following scenario:
        class A {
            __int64 field_0x00;
            __int64 field_0x08;
        }

        // B inherits field_0x00 and field_0x08 from its superclass so its fields start at 0x10
        class B : A {
            __int64 field_0x10;
            __int64 field_0x18;
        }
        """
        assert self.class_size % consts.WORD_SIZE == 0, 'invalid class_size!'

        # If this is not a subclass then data fields are going to start after the vptr
        start_offset = self.superclass.class_size if self.is_subclass() else consts.WORD_SIZE

        for offset in range(start_offset, self.class_size, consts.WORD_SIZE):
            yield offset

    def ancestors(self, inclusive: bool = False) -> ['ClassInfo', None, None]:
        """A generator over all direct or indirect superclasses of this class.

        Ancestors are returned in order from root (most distance) to superclass (closest), and the
        class itself is not returned.

        Options:
            inclusive: If True, then this class is included in the iteration. Default is False.
        """
        if self.superclass:
            for ancestor in self.superclass.ancestors(inclusive=True):
                yield ancestor
        if inclusive:
            yield self

    def descendants(self, inclusive: bool = False) -> ['ClassInfo', None, None]:
        """A generator over all direct or indirect subclasses of this class.

        Descendants are returned in descending depth-first order: first a subclass will be
        returned, then all of its descendants, before going on to the next subclass of this class.

        Options:
            inclusive: If True, then this class is included in the iteration. Default is False.
        """
        if inclusive:
            yield self
        for subclass in self.subclasses:
            for descendant in subclass.descendants(inclusive=True):
                yield descendant


@dataclasses.dataclass
class VtableEntry:
    index: int
    entry_ea: int
    vmethod_ea: int
    pac_diversifier: int
    overrides: bool
    pure_virtual: bool


class VtableInfo:
    """
    Current design only allows a one-to-one relationship between a ClassInfo instance and a VtableInfo instance
    """

    CXA_PURE_VIRTUAL_EA: int = idc.BADADDR

    def __init__(self, vtable_ea: int, vtable_end_ea: int, class_info: ClassInfo | None = None):
        # Vtable EA is the offset 0 of the vtable (every vtable in the kernelcache starts with two nulls)
        self.vtable_ea = vtable_ea
        self.end_ea = vtable_end_ea

        self._cached_entries: list[VtableEntry] = []
        self._class_info = class_info

    def __len__(self):
        return self.length

    @property
    def class_info(self):
        return self._class_info

    @class_info.setter
    def class_info(self, class_info: 'ClassInfo'):
        if self._class_info:
            raise VtableHasClassError(f'vtable {self.vtable_ea:#x} is already associated with {self._class_info.class_name}')
        self._class_info = class_info

    @property
    def length(self) -> int:
        """
        This property is the number of bytes for the whole vtable
        """
        return self.end_ea - self.vtable_ea

    @property
    def start_ea(self) -> int:
        """
        The EA of the first actual method in the vtable
        """
        return self.vtable_ea + consts.VTABLE_FIRST_METHOD_OFFSET

    @property
    def num_vmethods(self) -> int:
        assert self.length % consts.WORD_SIZE == 0, f'Invalid vtable length {self.length} for {self.class_info.class_name}!'
        return self.length // consts.WORD_SIZE

    @property
    def entries(self) -> list[VtableEntry]:

        # If we already calculated the entries we can return them
        if self._cached_entries:
            return self._cached_entries

        # If this vtable belongs to a subclass of some other class we can determine which functions have been overridden
        superclass_vtable_info = None
        if self.class_info.is_subclass():
            superclass_vtable_info = self.class_info.superclass.vtable_info

        for index, vtable_entry_ea, vmethod_ea in self.vmethods():
            pure_virtual = vmethod_ea == self.CXA_PURE_VIRTUAL_EA
            signed_ptr = ida_bytes.get_original_qword(vtable_entry_ea)
            if signed_ptr == vmethod_ea:
                # raise PhaseException(f'vmethod at {vtable_entry_ea:#x} does not seem to be a signed PAC pointer')
                log.error(f'vmethod at {vtable_entry_ea:#x} does not seem to be a signed PAC pointer')
                pac_diversifier = -1
            else:
                pac_diversifier = utils.get_pac(signed_ptr)
            overrides = False
            if superclass_vtable_info and index < len(superclass_vtable_info.entries):
                super_vtable_entry = superclass_vtable_info.entries[index]
                overrides = super_vtable_entry.vmethod_ea != vmethod_ea

            # Create a new vtable entry
            vtable_entry = VtableEntry(index, vtable_entry_ea, vmethod_ea, pac_diversifier, overrides, pure_virtual)

            # Store it in the cached entries
            self._cached_entries.append(vtable_entry)

        return self._cached_entries

    def vmethods(self) -> (tuple[int, int], None, None):
        """
        This generator yields all the vmethods in the vtable with their addresses
        tuple[index, vtable_entry_ea, vmethod_ea]

        Consider the following demo vtable:

        Linear Address     DCQ
        0xFFFFFFFFFFFF0000 0xFFFFFFFF41414141 OSObject::vmethod_0
        0xFFFFFFFFFFFF0008 0xFFFFFFFF42424242 OSObject::vmethod_1
        0xFFFFFFFFFFFF0010 0xFFFFFFFF43434343 OSObject::vmethod_2
        0xFFFFFFFFFFFF0018 0xFFFFFFFF44444444 OSObject::vmethod_3

        This generator shall yield the following values:
        (0, FFFFFFFFFFFF0000, 0xFFFFFFFF41414141)
        (1, FFFFFFFFFFFF0008, 0xFFFFFFFF42424242)
        (2, FFFFFFFFFFFF0010, 0xFFFFFFFF43434343)
        (3, FFFFFFFFFFFF0018, 0xFFFFFFFF44444444)
        """
        for index, (vtable_entry_ea, vmethod_ea) in enumerate(generators.ReadWords(self.start_ea, self.end_ea, addresses=True)):
            yield index, vtable_entry_ea, vmethod_ea


class ClassInfoMap:
    """
    Allows us to index the ClassInfo instances both by classname and by metaclass ea
    The usage is simple, but don't confuse this map with a standard dictionary because except of some helper magic methods
    that I have overwritten it does not behave like a normal dict

    Wrong usage would lead to TypeError being raised
    """

    def __init__(self):
        super().__init__()
        self._keys: set[tuple[int, str]] = set()

        # A global map from metaclass_ea to ClassInfo objects.
        self.metaclass_ea_to_class_info: dict[int, ClassInfo] = {}

        # A global map from class names to ClassInfo objects.
        self.classname_to_class_info: dict[str, ClassInfo] = {}
        self._key_type_to_dict: dict[type, dict] = {
            int: self.metaclass_ea_to_class_info,
            str: self.classname_to_class_info
        }

    def _get_dict_from_type(self, key_type: type) -> dict:
        if key_type not in self._key_type_to_dict:
            raise TypeError(f'{self.__class__.__name__} allows int or str keys only!')
        return self._key_type_to_dict[key_type]

    def _get_dict_from_key(self, key: int | str) -> dict:
        return self._get_dict_from_type(type(key))

    def __setitem__(self, key: tuple[int, str], value):
        if not isinstance(key, tuple) or len(key) != 2:
            raise TypeError(f'Every key in this mapping must be of type: tuple[str, int]')

        self._keys.add(key)
        self.metaclass_ea_to_class_info.__setitem__(key[0], value)
        self.classname_to_class_info.__setitem__(key[1], value)

    def __getitem__(self, key) -> ClassInfo:
        d = self._get_dict_from_key(key)
        return d.__getitem__(key)

    def __contains__(self, key):
        d = self._get_dict_from_key(key)
        return d.__contains__(key)

    def __len__(self):
        assert len(self.metaclass_ea_to_class_info) == len(self.classname_to_class_info), 'Invalid state, inner mappings does not match in length'
        return self.metaclass_ea_to_class_info.__len__()

    def __bool__(self):
        return all(bool(d) for d in self._key_type_to_dict.values())

    def clear(self):
        self._keys.clear()
        for d in self._key_type_to_dict.values():
            d.clear()

    def add_classinfo(self, new_class_info: ClassInfo):
        """
        Just a helper method to index this class info in this map by both its classname and its metaclass_ea
        """
        assert new_class_info.class_name, 'invalid classname'
        assert new_class_info.metaclass_ea, 'invalid metaclass_ea'

        self[(new_class_info.metaclass_ea, new_class_info.class_name)] = new_class_info

    def items_by_type(self, key_type: type):
        d = self._get_dict_from_type(key_type)
        return d.items()

    def items(self) -> (tuple[int, str, ClassInfo], None, None):
        for key in self._keys:
            value1, value2 = self[key[0]], self[key[1]]
            assert value1 == value2, f'invalid state in ClassInfoMap for key {key}'
            yield key[0], key[1], value1

    def keys(self) -> (tuple[int, str], None, None):
        for key in self._keys:
            yield key

    def values(self):
        # It shouldn't matter which internal dictionary we use here
        return self.metaclass_ea_to_class_info.values()

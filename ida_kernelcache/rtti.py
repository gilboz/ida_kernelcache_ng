"""
ida_kernelcache/rtti.py
Author: Brandon Azad, gilboz

This module defines the ClassInfo, VtableInfo and ClassInfoMap classes.
These classes are responsible for storing information about a C++ RTTI information in the kernelcache.

The ClassInfoMap is meant to hold all of this information in an easy to use and fast data structure.
It uses both metaclass_ea and classname as indexes to the ClassInfo instances that are created in the CollectClasses phase
"""
import enum
import json
import logging
import dataclasses
import pathlib
from collections import deque
from typing import Generator

import ida_bytes
import ida_funcs
import ida_nalt
import idc

from ida_kernelcache import consts, utils
from ida_kernelcache.exceptions import ClassHasVtableError, VtableHasClassError, PhaseException
from ida_kernelcache.ida_helpers import generators, functions

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

    def serialize(self) -> dict:
        return {
            'class_name': self.class_name,
            'metaclass_ea': self.metaclass_ea,
            'class_size': self.class_size,
            'super_metaclass_ea': self.superclass.metaclass_ea if self.superclass else None,
            'vtable_info': self.vtable_info.serialize() if self.vtable_info else None,
        }

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


class SymbolSource(enum.IntEnum):
    NO_SYMBOL = 0
    PAC_DB = enum.auto()
    IPSW_DB = enum.auto()
    IPSW_PROPAGATION = enum.auto()


@dataclasses.dataclass
class VMethodInfo:
    vmethod_ea: int
    vtable_entries: list['VtableEntry'] = dataclasses.field(default_factory=list, repr=False)  # The relationship between vmethod and vtable entries is one-to-many
    mangled_symbol: str | None = None  # A mangled symbol if known, None otherwise
    symbol_source: SymbolSource = SymbolSource.NO_SYMBOL  # An enumeration type specifying the symbol source if this vmethod has one
    func: ida_funcs.func_t | None = dataclasses.field(init=False)  # Easy access to IDA function structure. None if the vmethod_ea is not the function start address

    def __post_init__(self):
        if functions.is_function_start(self.vmethod_ea):
            self.func = ida_funcs.get_func(self.vmethod_ea)
        else:
            self.func = None

    def __hash__(self):
        return hash(self.vmethod_ea)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.vmethod_ea == other.vmethod_ea

    def __repr__(self) -> str:
        return f'VMethodInfo(vmethod_ea={self.vmethod_ea:#x}, mangled_symbol={self.mangled_symbol}, symbol_source={self.symbol_source}, valid={self.func is not None}, vtable_entries={len(self.vtable_entries)})'


@dataclasses.dataclass
class VtableEntry:
    index: int  # The index of the vtable entry in the current vtable
    entry_ea: int  # Address of the entry in the virtual table
    vmethod_ea: int  # Address of the virtual method that the vtable entry points to
    inherited: bool  # This method was inherited from the superclass
    overrides: bool  # This method overrides its super implementation
    added: bool  # First time we are seeing this method in this inheritance chain
    pure_virtual: bool  # This is a pure virtual method
    vmethod_info: VMethodInfo | None = dataclasses.field(default=None)
    pac_diversifier: int = dataclasses.field(init=False)  # The pac diversifier of the current vtable entry

    def __post_init__(self):
        signed_ptr = ida_bytes.get_original_qword(self.entry_ea)
        if signed_ptr != self.vmethod_ea:
            self.pac_diversifier = utils.get_pac(signed_ptr)
        else:
            log.error(f'vtable entry at {self.entry_ea:#x} has contains a non-PACed vmethod ptr {signed_ptr:#x}')
            self.pac_diversifier = -1

    def __hash__(self):
        return hash(self.entry_ea)

    def __eq__(self, other):
        return self.entry_ea == other.entry_ea

    def __repr__(self) -> str:
        has_symbol = int(bool(self.vmethod_info and self.vmethod_info.mangled_symbol))
        return f'VtableEntry(index={self.index}, entry_ea={self.entry_ea:#x}, pac_diversifier={self.pac_diversifier:#x}, o={int(self.overrides)}, i={int(self.inherited)}, pv={int(self.pure_virtual)}, a={int(self.added)}, symbolicated={has_symbol})'


class VtableInfo:
    """
    Current design only allows a one-to-one relationship between a ClassInfo instance and a VtableInfo instance
    """

    CXA_PURE_VIRTUAL_EA: int = idc.BADADDR

    def __init__(self, vtable_ea: int, vtable_end_ea: int, has_sentinel: bool = False, class_info: ClassInfo | None = None):
        # Vtable EA is the offset 0 of the vtable (every vtable in the kernelcache starts with two nulls)
        self.vtable_ea = vtable_ea
        self.end_ea = vtable_end_ea
        self.has_sentinel = has_sentinel
        self._cached_entries: list[VtableEntry] = []
        self._class_info = class_info

    def serialize(self) -> dict:
        return {
            'vtable_ea': self.vtable_ea,
            'end_ea': self.end_ea,
            'has_sentinel': self.has_sentinel
        }

    def __len__(self):
        return self.total_length

    @property
    def class_info(self) -> ClassInfo | None:
        return self._class_info

    @class_info.setter
    def class_info(self, class_info: 'ClassInfo'):
        if self._class_info:
            raise VtableHasClassError(f'vtable {self.vtable_ea:#x} is already associated with {self._class_info.class_name}')
        self._class_info = class_info

    @property
    def total_length(self) -> int:
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
    def actual_length(self) -> int:
        """
        This property is the number of bytes for the vmethods section only (excluding first 16 bytes of zeros)
        """
        return self.end_ea - self.start_ea

    @property
    def num_vmethods(self) -> int:
        assert self.actual_length % consts.WORD_SIZE == 0, f'Invalid vtable length {self.actual_length} for {self.class_info.class_name}!'
        return self.actual_length // consts.WORD_SIZE

    def _vmethods(self) -> (tuple[int, int], None, None):
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

    @property
    def entries(self) -> list[VtableEntry]:
        assert self.CXA_PURE_VIRTUAL_EA != idc.BADADDR, 'Forgot to initialize the __cxa_pure_virtual ea!'
        # If we already calculated the entries we can return them
        if self._cached_entries:
            return self._cached_entries

        # If this vtable belongs to a subclass of some other class we can determine which functions have been overridden
        superclass_vtable_info = None
        if self.class_info.is_subclass():
            superclass_vtable_info = self.class_info.superclass.vtable_info

        for index, vtable_entry_ea, vmethod_ea in self._vmethods():
            pure_virtual = vmethod_ea == self.CXA_PURE_VIRTUAL_EA

            inherited, overrides, added = False, False, True
            if superclass_vtable_info and index < superclass_vtable_info.num_vmethods:
                super_vtable_entry = superclass_vtable_info.entries[index]
                inherited = super_vtable_entry.vmethod_ea == vmethod_ea
                overrides = super_vtable_entry.vmethod_ea != vmethod_ea
                added = False

            # Create a new vtable entry
            vtable_entry = VtableEntry(index, vtable_entry_ea, vmethod_ea, inherited, overrides, added, pure_virtual)

            # Store it in the cached entries
            self._cached_entries.append(vtable_entry)

        return self._cached_entries

    def related_entries(self, vtable_entry: VtableEntry) -> Generator[tuple[ClassInfo, VtableEntry], None, None]:
        """
        Generator that returns "related" VtableEntries. That is vtable entries of ancestors or descendants with the
        same vtable index. First it will traverse up the inheritance tree and then down
        """
        assert vtable_entry.index <= self.num_vmethods, 'Invalid vtable entry!'
        assert vtable_entry.overrides or vtable_entry.added, 'Invalid vtable entry type!'

        # Traversing upwards only makes sense when the vtable entry overrides
        if vtable_entry.overrides:
            for class_info in self._class_info.ancestors(inclusive=False):
                # Classes close to the root of the inheritance tree might not have this vtable entry
                if vtable_entry.index >= class_info.vtable_info.num_vmethods:
                    continue

                super_vtable_entry = class_info.vtable_info.entries[vtable_entry.index]

                yield class_info, super_vtable_entry

        # Traversing downwards we may find both vtable entries that inherit or overrides this vtable entry
        # We are interested in
        for class_info in self.class_info.descendants(inclusive=False):

            # There are very little classes that have subclasses without vtable information we should handle them
            if class_info.vtable_info is None:
                continue

            sub_vtable_entry = class_info.vtable_info.entries[vtable_entry.index]
            if sub_vtable_entry.overrides:
                yield class_info, sub_vtable_entry


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

    def items_by_type(self, key_type: type) -> (tuple[str | int, ClassInfo], None, None):
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

    def bfs(self, must_have_vtable: bool = True) -> Generator[ClassInfo, None, None]:
        queue: deque[ClassInfo] = deque((ci for ci in self.values() if ci.superclass is None))
        while queue:
            class_info = queue.popleft()

            # Skip classes without vtable information
            if must_have_vtable and class_info.vtable_info is None:
                continue

            yield class_info

            # Add the next level of classes to the end of the deque
            for subclass in class_info.subclasses:
                queue.append(subclass)


class VMethodInfoMap:
    """
    A data storage class to maintain a global unique instance for every vmethod.
    The vmethods are indexed by the vmethod_ea which is unique and therefore may be used as a primary key.
    """

    def __init__(self):
        self._vmethods: dict[int, VMethodInfo] = {}

    def clear(self):
        self._vmethods.clear()

    def _create_vmethod_info(self, vmethod_ea: int) -> None:
        assert vmethod_ea not in self._vmethods, 'vmethod already exists in the map!'
        vmethod_info = VMethodInfo(vmethod_ea, [], None, SymbolSource.NO_SYMBOL)
        self._vmethods[vmethod_ea] = vmethod_info

    def get_vmethod(self, vmethod_ea: int, create: bool = True) -> VMethodInfo:
        """
        Get an existing VMethodInfo instance by the vmethod_ea. Will create a new one if it doesn't already exist if the `create` parameter is set to True.
        """
        if vmethod_ea not in self._vmethods and create:
            self._create_vmethod_info(vmethod_ea)
        return self._vmethods[vmethod_ea]

    def add_relation(self, vtable_entry: VtableEntry, create: bool = True) -> None:
        assert vtable_entry.vmethod_info is None, 'VtableEntry already has a VMethodInfo instance!'
        vmethod_info = self.get_vmethod(vtable_entry.vmethod_ea, create)
        vmethod_info.vtable_entries.append(vtable_entry)
        vtable_entry.vmethod_info = vmethod_info

    def __len__(self) -> int:
        return len(self._vmethods)

    def items(self):
        return self._vmethods.items()

    def keys(self):
        return self._vmethods.keys()

    def values(self):
        return self._vmethods.values()

    @property
    def num_symbolicated(self):
        """
        Returns the number of symbolicated vmethods
        """
        num = 0
        for vmethod_info in self._vmethods.values():
            if vmethod_info.mangled_symbol:
                num += 1
        return num


class RTTIDatabase:
    RTTI_DB_SUFFIX = '.rtti_db.json'

    def __init__(self):
        self.class_info_map = ClassInfoMap()
        self.vmethod_info_map = VMethodInfoMap()
        self.persistent_path = pathlib.Path(ida_nalt.get_input_file_path() + self.RTTI_DB_SUFFIX)

    def save(self):
        class_dicts = []
        for class_info in self.class_info_map.values():
            class_dicts.append(class_info.serialize())

        offsets = {
            'cxa_pure_virtual_ea': VtableInfo.CXA_PURE_VIRTUAL_EA
        }

        with self.persistent_path.open('w') as f:
            json.dump({'classes': class_dicts, 'offsets': offsets}, f)
            log.info(f'RTTI Database saved to {self.persistent_path}')

    def load(self):
        if not self.persistent_path.exists():
            return

        log.info('RTTI Database loading..')
        with self.persistent_path.open('r') as f:
            try:
                d = json.load(f)
            except json.JSONDecodeError:
                log.error(f'RTTI Database at {self.persistent_path} is not a valid JSON!')
                return
        try:
            # Restore the cxa_pure_virtual address, which will be used to determine if a vtable entry is pure virtual
            VtableInfo.CXA_PURE_VIRTUAL_EA = d['offsets']['cxa_pure_virtual_ea']

            # Load class info
            for class_dict in d['classes']:
                new_class_info = ClassInfo(class_dict['class_name'], class_dict['metaclass_ea'], class_dict['class_size'])
                self.class_info_map.add_classinfo(new_class_info)

            # Reconstruct inheritance tree
            for class_dict in d['classes']:
                super_metaclass_ea = class_dict['super_metaclass_ea']
                if super_metaclass_ea:
                    class_info = self.class_info_map[class_dict['metaclass_ea']]
                    superclass_info = self.class_info_map[super_metaclass_ea]
                    class_info.superclass = superclass_info
                    superclass_info.subclasses.add(class_info)

            # Load vtable info
            for class_dict in d['classes']:
                class_info = self.class_info_map[class_dict['metaclass_ea']]
                vtable_dict = class_dict['vtable_info']
                if vtable_dict:
                    new_vtable_info = VtableInfo(vtable_dict['vtable_ea'], vtable_dict['end_ea'], vtable_dict['has_sentinel'])
                    class_info.vtable_info = new_vtable_info
                    new_vtable_info.class_info = class_info

                    for vtable_entry in new_vtable_info.entries:
                        self.vmethod_info_map.add_relation(vtable_entry)
        except KeyError:
            log.error(f'RTTI Database at {self.persistent_path} has an invalid format!')
            self.class_info_map.clear()
            self.vmethod_info_map.clear()
        else:
            log.info(f'RTTI Database restored: {len(self.class_info_map)} classes loaded')

"""
ida_kernelcache/rtti_info.py
Author: Brandon Azad, gilboz

This module defines the ClassInfo, VtableInfo and ClassInfoMap classes.
These classes are responsible for sotring information about a C++ RTTI information in the kernelcache.

The ClassInfoMap is meant to hold all of this information in an easy to use and fast data structure.
It uses both metaclass_ea and classname as indexes to the ClassInfo instances that are created in the CollectClasses phase
"""
from ida_kernelcache import consts
from ida_kernelcache.exceptions import ClassHasVtableError, VtableHasClassError


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
    def vtable_info(self):
        return self._vtable_info

    @vtable_info.setter
    def vtable_info(self, vtable_info: 'VtableInfo'):
        if self._vtable_info:
            raise ClassHasVtableError(f'{self.class_name} is already associated with vtable at {self._vtable_info.vtable_ea:#x}')
        self._vtable_info = vtable_info

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


class VtableInfo:
    """
    Current design only allows a one-to-one relationship between a ClassInfo instance and a VtableInfo instance
    """

    def __init__(self, vtable_ea: int, vtable_end_ea: int, class_info: ClassInfo | None = None):
        self.vtable_ea = vtable_ea
        self.vtable_end_ea = vtable_end_ea
        self._class_info = class_info

    def __len__(self):
        return self.vtable_length

    @property
    def class_info(self):
        return self._class_info

    @class_info.setter
    def class_info(self, class_info: 'ClassInfo'):
        if self._class_info:
            raise VtableHasClassError(f'vtable {self.vtable_ea:#x} is already associated with {self._class_info.class_name}')
        self._class_info = class_info

    @property
    def vtable_length(self) -> int:
        """
        This property is the number of bytes for the whole vtable
        """
        return self.vtable_end_ea - self.vtable_ea

    @property
    def vtable_methods_start(self) -> int:
        """
        The EA of the first actual method in the vtable
        """
        return self.vtable_ea + consts.VTABLE_FIRST_METHOD_OFFSET

    @property
    def vtable_num_methods(self) -> int:
        assert self.vtable_length % consts.WORD_SIZE == 0, f'Invalid vtable length {self.vtable_length} for {self.class_name}!'
        return self.vtable_length // consts.WORD_SIZE


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

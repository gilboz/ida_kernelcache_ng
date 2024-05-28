"""

ida_kernelcache/class_info.py
Author: Brandon Azad

This module defines the ClassInfo class, which stores information about a C++ class in the
kernelcache. It also provides the function collect_class_info() to scan the kernelcache for
information about C++ classes and populate global variables with the result.
"""

import ida_kernelcache.ida_utilities as idau
from ida_kernelcache import (
    ida_utilities as idau,
    consts
)

class ClassInfo(object):
    """
    Python class to store C++ class information from KernelCache.
    """

    def __init__(self, classname, metaclass, vtable, vtable_length, class_size, superclass_name, meta_superclass):
        self.superclass = None
        self.subclasses = set()
        self.classname = classname
        self.metaclass = metaclass
        self.vtable = vtable
        self.vtable_length = vtable_length
        self.class_size = class_size
        self.superclass_name = superclass_name
        self.meta_superclass = meta_superclass

    def __repr__(self):
        def hex(x):
            if x is None:
                return repr(None)
            return f'{x:#x}'

        return 'ClassInfo({!r}, {}, {}, {}, {}, {!r}, {})'.format(
            self.classname, hex(self.metaclass), hex(self.vtable),
            self.vtable_length, self.class_size, self.superclass_name,
            hex(self.meta_superclass))

    @property
    def vtable_methods(self):
        return self.vtable + consts.VTABLE_OFFSET * idau.WORD_SIZE

    @property
    def vtable_nmethods(self):
        if not self.vtable_length or self.vtable_length < consts.VTABLE_OFFSET:
            return 0
        return self.vtable_length - consts.VTABLE_OFFSET

    def ancestors(self, inclusive=False):
        """A generator over all direct or indircet superclasses of this class.

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

    def descendants(self, inclusive=False):
        """A generator over all direct or indircet subclasses of this class.

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

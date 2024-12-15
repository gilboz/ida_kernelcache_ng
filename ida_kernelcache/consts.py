from enum import IntEnum, auto


class KCFormat(IntEnum):
    NORMAL_11 = auto()
    MERGED_12 = auto()


# The first few entries of the virtual method tables in the kernelcache are empty.
VTABLE_OFFSET = 2
VTABLE_GETMETACLASS = VTABLE_OFFSET + 7

# The minimum number of methods in a virtual method table.
MIN_VTABLE_METHODS = 12

# The minimum length of a virtual method table in words, including the initial empty entries.
MIN_VTABLE_LENGTH = VTABLE_OFFSET + MIN_VTABLE_METHODS
MAX_GETMETACLASS_INSNS = 7

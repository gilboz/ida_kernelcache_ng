import idc
import ida_funcs

from ida_kernelcache.exceptions import PhaseException


def get_func_start(ea: int, raise_error: bool = True) -> int:
    f = ida_funcs.get_func(ea)
    if f is None:
        if raise_error:
            raise PhaseException(f'Failed to find function start address of {ea:#x}')
        else:
            return idc.BADADDR

    return f.start_ea

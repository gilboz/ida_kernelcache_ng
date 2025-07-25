
import ida_bytes
import idaapi
import idautils
import idc
import ida_funcs
import logging
from ida_kernelcache.exceptions import PhaseException
from ida_kernelcache.ida_helpers.instructions import get_previous

log = logging.getLogger(__name__)

def get_func_start(ea: int, raise_error: bool = True) -> int:
    f = ida_funcs.get_func(ea)
    if f is None:
        if raise_error:
            raise PhaseException(f'Failed to find function start address of {ea:#x}')
        else:
            return idc.BADADDR

    return f.start_ea


MAX_PREVIOUS_INSTRUCTIONS = 20


def get_func_start_or_try_create(ea: int) -> int:
    func_start = get_func_start(ea, raise_error=False)
    if func_start != idc.BADADDR:
        return func_start

    prev = get_previous(ea, "PAC", MAX_PREVIOUS_INSTRUCTIONS)
    if prev is None:
        raise PhaseException(
            f"Failed to find function start address of {ea:#x}, no PAC instruction before it."
        )

    if ida_funcs.add_func(prev) == 0:
        raise PhaseException(f"Failed to create function for address of {ea:#x}")

    return get_func_start(ea)


# TODO: Rework function creates and make them an initial stage

def _fix_unrecognized_function_insns(func):
    # Undefine every instruction that IDA does not recognize within the function
    while idc.find_func_end(func) == idc.BADADDR:
        func_properties = ida_funcs.func_t(func)
        ida_funcs.find_func_bounds(func_properties, ida_funcs.FIND_FUNC_DEFINE)
        unrecognized_insn = func_properties.end_ea
        if unrecognized_insn == 0:
            log.debug(f"Could not find unrecognized instructions for function at {func:#x}")
            return False

        # We found an unrecognized instruction, lets undefine it and explicitly make an instruction out of it!
        unrecognized_insn_end = ida_bytes.get_item_end(unrecognized_insn)
        log.debug(f'Undefining item {unrecognized_insn:#x} - {unrecognized_insn_end:#x}')
        ida_bytes.del_items(unrecognized_insn, ida_bytes.DELIT_EXPAND)
        if idc.create_insn(unrecognized_insn) == 0:
            log.debug(f"Could not convert data at {unrecognized_insn:#x} to instruction")
            return False

    return True


def _convert_address_to_function(func):
    """
    Convert an address that IDA has classified incorrectly into a proper function."""
    # If everything goes wrong, we'll try to restore this function.
    orig = idc.first_func_chunk(func)
    if idc.find_func_end(func) == idc.BADADDR:
        # Could not find function end, probably because IDA parsed an instruction
        # in the middle of the function incorrectly as data. Lets try to fix the relevant insns.
        _fix_unrecognized_function_insns(func)

    else:
        # Just try removing the chunk from its current function. IDA can add it to another function
        # automatically, so make sure it's removed from all functions by doing it in loop until it
        # fails.
        for i in range(1024):
            if not idc.remove_fchunk(func, func):
                break
    # Now try making a function.
    if ida_funcs.add_func(func) != 0:
        return True
    # This is a stubborn chunk. Try recording the list of chunks, deleting the original function,
    # creating the new function, then re-creating the original function.
    if orig != idc.BADADDR:
        chunks = list(idautils.Chunks(orig))
        if ida_funcs.del_func(orig) != 0:
            # Ok, now let's create the new function, and recreate the original.
            if ida_funcs.add_func(func) != 0:
                if ida_funcs.add_func(orig) != 0:
                    # Ok, so we created the functions! Now, if any of the original chunks are not
                    # contained in a function, we'll abort and undo.
                    if all(idaapi.get_func(start) for start, end in chunks):
                        return True
            # Try to undo the damage.
            for start, _ in chunks:
                ida_funcs.del_func(start)
    # Everything we've tried so far has failed. If there was originally a function, try to restore
    # it.
    if orig != idc.BADADDR:
        log.debug(f'Trying to restore original function {orig:#x}')
        ida_funcs.add_func(orig)
    return False


def is_function_start(ea: int) -> bool:
    """
    Return True if the address is the start of a function
    """
    return idc.get_func_attr(ea, idc.FUNCATTR_START) == ea


def force_function(addr) -> bool:
    """
    Ensure that the given address is a function type, converting it if necessary.
    """
    if is_function_start(addr):
        return True
    return _convert_address_to_function(addr)

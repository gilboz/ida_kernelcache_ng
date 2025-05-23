import idaapi
import idc
import ida_bytes
import ida_name

from ida_kernelcache import consts
from ida_kernelcache.exceptions import DemanglingError


def get_name_ea(name, fromaddr=idc.BADADDR):
    """
    Get the address of a name.

    This function returns the linear address associated with the given name.

    Arguments:
        name: The name to look up.

    Options:
        fromaddr: The referring address. Default is BADADDR. Some addresses have a
            location-specific name (for example, labels within a function). If fromaddr is not
            BADADDR, then this function will try to retrieve the address of the name from
            fromaddr's perspective. If name is not a local name, its address as a global name will
            be returned.

    Returns:
        The address of the name or BADADDR.
    """
    return idc.get_name_ea(fromaddr, name)


def get_ea_name(ea, fromaddr=idc.BADADDR, true=False, user=False):
    """
    Get the name of an address.

    This function returns the name associated with the byte at the specified address.

    Arguments:
        ea: The linear address whose name to find.

    Options:
        fromaddr: The referring address. Default is BADADDR. Some addresses have a
            location-specific name (for example, labels within a function). If fromaddr is not
            BADADDR, then this function will try to retrieve the name of ea from fromaddr's
            perspective. The global name will be returned if no location-specific name is found.
        true: Retrieve the true name rather than the display name. Default is False.
        user: Return "" if the name is not a user name.

    Returns:
        The name of the address or "".
    """
    if user and not idc.hasUserName(ida_bytes.get_full_flags(ea)):
        return ""
    if true:
        return ida_name.get_ea_name(fromaddr, ea)
    else:
        return idc.get_name(ea, ida_name.GN_VISIBLE | idc.calc_gtn_flags(fromaddr, ea))


def set_ea_name(ea, name, rename=False, auto=False):
    """
    Set the name of an address.

    Arguments:
        ea: The address to name.
        name: The new name of the address.

    Options:
        rename: If rename is False, and if the address already has a name, and if that name differs
            from the new name, then this function will fail. Set rename to True to rename the
            address even if it already has a custom name. Default is False.
        auto: If auto is True, then mark the new name as autogenerated. Default is False.

    Returns:
        True if the address was successfully named (or renamed).
    """
    if not rename and idc.hasUserName(ida_bytes.get_full_flags(ea)):
        return get_ea_name(ea) == name
    flags = idc.SN_CHECK
    if auto:
        flags |= idc.SN_AUTO
    return bool(idc.set_name(ea, name, flags))


def demangle(mangled_symbol: str) -> str:

    # TODO: understand why the compiler emits symbols that are not conforming to the ABI
    # Cannot demangle symbols that end with _vfpthunk_
    if mangled_symbol.endswith(consts.VFPTHUNK_SUFFIX):
        mangled_symbol = mangled_symbol.rstrip(consts.VFPTHUNK_SUFFIX)

    demangled_symbol = ida_name.demangle_name(mangled_symbol, 0, ida_name.DQT_FULL)
    if demangled_symbol:
        return demangled_symbol
    raise DemanglingError(f'Failed to demangle {mangled_symbol}!')

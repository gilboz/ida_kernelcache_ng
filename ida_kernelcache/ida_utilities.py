
def struct_create(name, union=False):
    """
    Create an IDA struct with the given name, returning the SID."""
    # AddStrucEx is documented as returning -1 on failure, but in practice it seems to return
    # BADADDR.
    union = 1 if union else 0
    sid = idc.add_struc(-1, name, union)
    if sid in (-1, idc.BADADDR):
        return None
    return sid


def struct_open(name, create=False, union=None):
    """
    Get the SID of the IDA struct with the given name, optionally creating it."""
    sid = ida_struct.get_struc_id(name)
    if sid == idc.BADADDR:
        if not create:
            return None
        sid = struct_create(name, union=bool(union))
    elif union is not None:
        is_union = bool(idc.is_union(sid))
        if union != is_union:
            return None
    return sid

def struct_member_offset(sid, name):
    """
    A version of IDA's GetMemberOffset() that also works with unions."""
    struct = idaapi.get_struc(sid)
    if not struct:
        return None
    member = idaapi.get_member_by_name(struct, name)
    if not member:
        return None
    return member.soff


def struct_add_word(sid, name, offset, size, count=1):
    """
    Add a word (integer) to a structure.

    If sid is a union, offset must be -1.
    """
    return idc.add_struc_member(sid, name, offset, idc.FF_DATA | word_flag(size), -1, size * count)


def struct_add_ptr(sid, name, offset, count=1, type=None):
    """
    Add a pointer to a structure.

    If sid is a union, offset must be -1.
    """
    ptr_flag = idc.FF_DATA | word_flag(WORD_SIZE) | ida_bytes.off_flag()
    ret = idc.add_struc_member(sid, name, offset, ptr_flag, 0, WORD_SIZE)
    if ret == 0 and type is not None:
        if offset == -1:
            offset = struct_member_offset(sid, name)
            assert offset is not None
        mid = idc.get_member_id(sid, offset)
        idc.SetType(mid, type)
    return ret


def struct_add_struct(sid, name, offset, msid, count=1):
    """
    Add a structure member to a structure.

    If sid is a union, offset must be -1.
    """
    size = ida_struct.get_struc_size(msid)
    return idc.add_struc_member(sid, name, offset, idc.FF_DATA | ida_bytes.FF_STRUCT, msid, size * count)

import idc
import ida_typeinf


def does_type_exist(type_name: str) -> bool:
    return idc.get_struc_id(type_name) != idc.BADADDR


def create_type_from_decl(type_decl: str):
    pass

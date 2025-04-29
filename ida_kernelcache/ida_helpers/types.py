import ida_nalt
import idc
import ida_typeinf

from ida_kernelcache.exceptions import FailedToCreateTypeError, LocalTypeError, TypeNotFoundError, FuncTypeError


def does_type_exist(type_name: str) -> bool:
    return idc.get_struc_id(type_name) != idc.BADADDR


def create_type_from_decl(type_decl: str, replace: bool = False):
    """
    #define PT_SIL       0x0001  ///< silent, no messages
    #define PT_NDC       0x0002  ///< don't decorate names
    #define PT_TYP       0x0004  ///< return declared type information
    #define PT_VAR       0x0008  ///< return declared object information
    #define PT_PACKMASK  0x0070  ///< mask for pack alignment values
    #define PT_HIGH      0x0080  ///< assume high level prototypes
                                 ///< (with hidden args, etc)
    #define PT_LOWER     0x0100  ///< lower the function prototypes
    #define PT_REPLACE   0x0200  ///< replace the old type (used in idc)
    #define PT_RAWARGS   0x0400  ///< leave argument names unchanged (do not remove underscores)
    #define PT_RELAXED   0x1000  ///< accept references to unknown namespaces
    #define PT_EMPTY     0x2000  ///< accept empty decl
    """
    pt_flags = 0
    if replace:
        pt_flags |= ida_typeinf.PT_REPLACE
    num_errors = ida_typeinf.idc_parse_types(type_decl, pt_flags)
    if num_errors:
        raise FailedToCreateTypeError(f'Got {num_errors} num errors')


class LocalType:

    def __init__(self, type_name: str):
        self.type_name = type_name
        self.tif = ida_typeinf.tinfo_t()
        if not self.tif.get_named_type(None, type_name):
            raise TypeNotFoundError(f'Could not find {type_name}')

        if not self.tif.is_struct() or not self.tif.is_udt():
            raise LocalTypeError(f'{type_name} is not a UDT struct!')

        self.tid = self.tif.get_tid()
        self.ordinal = ida_typeinf.get_tid_ordinal(self.tid)

        # Members related fields
        self.udt = ida_typeinf.udt_type_data_t()
        self.tif.get_udt_details(self.udt)
        self.num_members = self.udt.size()

    def lookup_type(self, ):
        """
        #define NTF_TYPE       0x0001   ///< type name
        #define NTF_SYMU       0x0008   ///< symbol, name is unmangled ('func')
        #define NTF_SYMM       0x0000   ///< symbol, name is mangled ('_func');
                                        ///< only one of #NTF_TYPE and #NTF_SYMU, #NTF_SYMM can be used
        #define NTF_NOBASE     0x0002   ///< don't inspect base tils (for get_named_type)
        #define NTF_REPLACE    0x0004   ///< replace original type (for set_named_type)
        #define NTF_UMANGLED   0x0008   ///< name is unmangled (don't use this flag)
        #define NTF_NOCUR      0x0020   ///< don't inspect current til file (for get_named_type)
        #define NTF_64BIT      0x0040   ///< value is 64bit
        #define NTF_FIXNAME    0x0080   ///< force-validate the name of the type when setting
                                        ///< (set_named_type, set_numbered_type only)
        #define NTF_IDBENC     0x0100   ///< the name is given in the IDB encoding;
                                        ///< non-ASCII bytes will be decoded accordingly
                                        ///< (set_named_type, set_numbered_type only)
        #define NTF_CHKSYNC    0x0200   ///< check that synchronization to IDB passed OK
                                        ///< (set_numbered_type, set_named_type)
        #define NTF_NO_NAMECHK 0x0400   ///< do not validate type name
                                        ///< (set_numbered_type, set_named_type)
        #define NTF_NOSYNC     0x0800   ///< do not sync type to IDB *-
                                        ///< (set_named_type, set_numbered_type only) *-
        #define NTF_COPY       0x1000   ///< save a new type definition, not a typeref (tinfo_t::set_numbered_type, tinfo_t::set_named_type)
        """

    def apply_fixups(self):
        pass

    def set_member_type(self, index: int, type_decl: str):
        if not type_decl.endswith(';'):
            type_decl += ';'

        member_tif = ida_typeinf.tinfo_t()

        # For some reason when the parsing is successful this method returns an empty str
        ret = ida_typeinf.parse_decl(member_tif, None, type_decl, ida_typeinf.PT_SIL)
        if ret is None:
            raise LocalTypeError(f'Failed to parse type declaration: {type_decl}')

        # tinfo_code_t 0 means ok
        if self.tif.set_udm_type(index, member_tif):
            raise LocalTypeError(f'Failed to change type of member of {self.type_name} at index {index} decl {type_decl}')

    def set_member_comment(self, index: int, comment: str):
        if self.tif.set_udm_cmt(index, comment):
            raise LocalTypeError(f'Failed to set member comment of {self.type_name} member {index}')

    def set_type_comment(self, comment: str):
        self.tif.set_type_cmt(comment)

    def __iter__(self):
        """
        Implement an easy method to iterate over this local type's members
        """
        pass


class FuncType:
    def __init__(self, func_ea: int):
        self.func_ea = func_ea
        self.tif = ida_typeinf.tinfo_t()
        if not ida_nalt.get_tinfo(self.tif, func_ea):
            raise FuncTypeError(f'Failed to get tinfo from {func_ea:#x}')

        if not self.tif.is_func():
            raise FuncTypeError(f'{self.tif} is not a function type!')

        # Note that func_type_data_t is a subclass of funcargvec_t
        # which is simply a vector of funcarg_t `typedef qvector<funcarg_t> funcargvec_t;`
        self.func_details = ida_typeinf.func_type_data_t()
        self.tif.get_func_details(self.func_details)

    def set_virtual(self):
        self.func_details.flags |= ida_typeinf.FTI_VIRTUAL

    def change_arg_type(self):
        assert len(self.func_details) >= 1, 'Function has less than 1 arguments. We must add the this argument'

    def set_this_arg(self, type_decl: str):
        func_arg = self.func_details[0]
        func_arg.name = 'this'
        func_arg.flags = ida_typeinf.FAI_HIDDEN

        # In IDA 9.0 SP1 they added the
        arg_tif = ida_typeinf.tinfo_t()

        # For some reason when the parsing is successful this method returns an empty str
        ret = ida_typeinf.parse_decl(arg_tif, None, type_decl, ida_typeinf.PT_SIL)
        if ret is None:
            raise LocalTypeError(f'Failed to parse type declaration: {type_decl}')

        func_arg.type = arg_tif


    def apply(self):
        """
        Apply the changes of the FuncType to the func_ea
        """
        self.tif.create_func(self.func_details)
        ida_typeinf.apply_tinfo(self.func_ea, self.tif, ida_typeinf.TINFO_DEFINITE)

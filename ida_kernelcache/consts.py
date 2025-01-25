MIN_IDA_SDK_VERSION = 900

# The size of a word on the current platform.
WORD_SIZE = 8

# The first few entries of the virtual method tables in the kernelcache are empty.
# TODO: Theoretically this can change (and therefore break) however it rarely happens
VTABLE_FIRST_METHOD_OFFSET = 2 * WORD_SIZE
VTABLE_GETMETACLASS_OFFSET = (2 + 7) * WORD_SIZE
INITIAL_NUM_VTABLE_METHODS = 7

# Related to C++ name mangling and symbols
OSMETACLASS_CTOR_SYMBOL = '__ZN11OSMetaClassC2EPKcPKS_j'
GLOBAL_METACLASS_INSTANCE_NAME = 'gMetaclass'
# Scope resolution operator
CXX_SCOPE = '::'

# Related to CreateTypes
CXA_PURE_VIRTUAL = '__cxa_pure_virtual'
VMETHOD_NAME_TEMPLATE = 'vmethod_{index}'
FIELD_SEP = '\n    '

VIRTUAL_FUNC_TEMPLATE = '__int64 (__fastcall *{func_name})({func_sig}); ///< {vmethod_ea:#x}'
VPTR_FIELD = 'void *__vftable;'
DATA_FIELD_TEMPLATE = '__int64 field_{offset:#04x};'
VTABLE_DECL_TEMPLATE = '''\
/// {vtable_ea:#x}
struct {class_name}_vtbl {{
    unsigned __int64 this_offset;
    void *rtti;
    {virtual_funcs}
}};'''

CPPOBJ_DECL_TEMPLATE = '''\
/// {metaclass_ea:#x}
struct __cppobj {class_name}{superclass_name} {{
    {data_fields}
}};'''

# This syntax was added in IDA 9.0 and it does work but we don't have real control about the fields of the vtable
CLASS_DECL_TEMPLATE = '''\
class {class_name}{superclass_name} {{
    virtual void this_offset();
    virtual void rtti();
    {virtual_funcs}
    {data_fields}
}};'''

# Related to ColorizeVtables
BGCOLOR_RED = 0x00008B
BGCOLOR_GREEN = 0x006400
BGCOLOR_BLUE = 0x8B0000
BGCOLOR_GRAY = 0x696969

VMETHOD_FUNC_CMT_TEMPLATE = '''\
############################################################################################################
# [ida_kernelcache_ng]
# This vmethod belongs to {owning_class}
# Owning vtable entry ea: {owning_vtable_entry_ea:#x}
# PAC Diversifier: {pac_diversifier:#x}
# Symbol Source: {symbol_source}
############################################################################################################
'''

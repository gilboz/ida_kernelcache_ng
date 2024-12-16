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
FUNC_NAME_TEMPlATE = 'vmethod_{index}'
VIRTUAL_FUNC_TEMPLATE = 'virtual __int64 {func_name}({func_sig});'
CLASS_DECL_TEMPLATE = '''\
class {class_name}{superclass_name} {{
{virtual_funcs}
{data_fields}
}};'''

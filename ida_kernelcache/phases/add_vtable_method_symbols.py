import idautils
import idc
import ida_kernelcache.ida_utilities as idau
from ida_kernelcache.symbol import global_name


def class_from_vtable_method_symbol(method_symbol):
    """
    Get the base class in a vtable method symbol.

    Extract the name of the base class from a canonical method symbol.
    """
    demangled = idc.demangle_name(method_symbol, idc.get_inf_attr(idc.INF_SHORT_DEMNAMES))
    if not demangled:
        return None
    classname = demangled.split('::', 1)[0]
    if classname == demangled:
        return None
    return classname


def _vtable_method_symbol_substitute_class(method_symbol, new_class, old_class=None):
    """
    Create a new method symbol by substituting the class to which the method belongs.
    """
    # TODO: This is wrong when the class name is repeated!
    if not old_class:
        old_class = class_from_vtable_method_symbol(method_symbol)
        if not old_class:
            return None
    old_class_part = '{}{}'.format(len(old_class), old_class)
    # new_class_part = '{}{}'.format(len(new_class), new_class)
    # TODO: this is a temp solution to have templated classes names resolved well. Need a permanent one.
    new_class_part = global_name(new_class).replace("__ZN", "").replace("__Z", "")
    if old_class_part not in method_symbol:
        return None
    return method_symbol.replace(old_class_part, new_class_part, 1)


_ignore_vtable_methods = (
    '___cxa_pure_virtual'
)


def _ok_to_rename_method(override, name):
    """
    Some method names are ok to rename.
    """
    return name.startswith('j_') and idau.iterlen(idautils.XrefsTo(override)) == 1


def _bad_name_dont_use_as_override(name):
    """
    Some names shouldn't propagate into vtable symbols.
    """
    # Ignore jumps and stubs and fixed known special values.
    return (name.startswith('j_') or stub.symbol_references_stub(name)
            or name in _ignore_vtable_methods)


def _symbolicate_overrides_for_classinfo(classinfo, processed):
    """A recursive function to symbolicate vtable overrides for a class and its superclasses."""
    # If we've already been processed, stop.
    if classinfo in processed:
        return
    # First propagate symbol information to our superclass.
    if classinfo.superclass:
        _symbolicate_overrides_for_classinfo(classinfo.superclass, processed)
    # Now symbolicate the superclass.
    for _, override, original in class_vtable_overrides(classinfo, methods=True):
        # Skip this method if the override already has a name and we can't rename it.
        override_name = idau.get_ea_name(override, user=True)
        if override_name and not _ok_to_rename_method(override, override_name):
            continue
        # Skip this method if the original does not have a name or if it's a bad name.
        original_name = idau.get_ea_name(original, user=True)
        if not original_name or _bad_name_dont_use_as_override(original_name):
            continue
        # Get the new override name if we substitute for the override class's name.
        new_name = _vtable_method_symbol_substitute_class(original_name, classinfo.classname)
        if not new_name:
            _log(0, 'Could not substitute class {} into method symbol {} for override {:#x}',
                 classinfo.classname, original_name, override)
            continue
        # Now that we have the new name, set it.
        if override_name:
            _log(2, 'Renaming {} -> {}', override_name, new_name)
        if not idau.set_ea_name(override, new_name, rename=True):
            _log(0, 'Could not set name {} for method {:#x}', new_name, override)
    # We're done.
    processed.add(classinfo)


def initialize_vtable_method_symbols():
    """Symbolicate overridden methods in a virtual method table.

    Propagate symbol names from the virtual method tables of the base classes.
    """
    # TODO: convert to a Phase class!
    processed = set()
    classes.collect_class_info()
    for classinfo in list(classes.class_info.values()):
        _symbolicate_overrides_for_classinfo(classinfo, processed)

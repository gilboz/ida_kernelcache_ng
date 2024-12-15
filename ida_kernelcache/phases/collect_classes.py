"""
ida_kernelcache/collect_classes.py
Author: Brandon Azad
Collects information about C++ classes in a kernelcache.
"""

import re

import idc
import idautils
import ida_xref
import ida_hexrays

from ida_kernelcache import ida_utilities as idau
from ida_kernelcache import class_info
from ida_kernelcache.emulate import emulate_arm64

from .base_phase import BasePhase
from ida_kernelcache.exceptions import PhaseException
from ida_kernelcache.utils import OneToOneMapFactory


class CollectClasses(BasePhase):
    """
    Collect information about C++ classes defined in a kernelcache. Arm64 only.

    This function searches through an iOS kernelcache for information about the C++ classes defined
    in it. It populates the global class_info dictionary, which maps the C++ class names to a
    ClassInfo object containing metainformation about the class.

    To force re-evaluation of the class_info dictionary, call class_info.clear() and then re-run
    this function.

    This function also collects the set of all virtual method tables identified in the kernelcache,
    even if the corresponding class could not be identified. A mapping from each virtual method
    table to its length is stored in the global vtables variable.

    Only Arm64 is supported at this time.

    TODO: what are nested classes?
    Only top-level classes are processed. Information about nested classes is not collected.
    """

    def __init__(self, kc):
        super().__init__(kc)

        # Collect associations from class names to metaclass instances and vice versa.
        self._metaclass_to_classname_builder = OneToOneMapFactory()
        self._metaclass_to_class_size = {}
        self._metaclass_to_meta_superclass = {}
        self._metaclass_info = {}

    def run(self):
        # Clear out old class information
        self._kc.classes.clear()

        self.log(1, 'Collecting information about OSMetaClass instances')
        self._collect_metaclasses()
        if not self._metaclass_info:
            raise PhaseException('Failed collecting OSMetaClass instances')

        self._kc.classes = self._metaclass_info.copy()

    def _found_metaclass(self, metaclass, classname, class_size, meta_superclass):

        # to handle names like (iOS17b1): "OSValueObject<H10ISP::client_log_buffer_t>"
        # TODO: handle in a better way
        prob_pattern = r"<(.*?)::(.*?)>"
        if re.search(prob_pattern, classname):
            # replaces the "::" by "_"
            classname = re.sub(prob_pattern, r"<\1_\2>", classname)

        self._metaclass_to_classname_builder.add_link(metaclass, classname)
        self._metaclass_to_class_size[metaclass] = class_size
        self._metaclass_to_meta_superclass[metaclass] = meta_superclass

    def _collect_metaclasses(self):
        """
        Collect OSMetaClass information from all kexts in the kernelcache.
        """
        old = idc.batch(1)
        try:
            self._collect_metaclasses_by_ctor_xrefs()
        finally:
            idc.batch(old)

        self._collect_metaclasses_from_init_func_sections()

        # Filter out any class name (and its associated metaclasses) that has multiple metaclasses.
        # This can happen when multiple kexts define a class but only one gets loaded.
        def bad_classname(classname, metaclasses):
            self.log(0, 'Class {} has multiple metaclasses: {}', classname,
                 ', '.join(['{:#x}'.format(mc) for mc in metaclasses]))

        # Filter out any metaclass (and its associated class names) that has multiple class names. I
        # have no idea why this would happen.
        def bad_metaclass(metaclass, classnames):
            self.log(0, 'Metaclass {:#x} has multiple classes: {}', metaclass, ', '.join(classnames))

        # Return the final dictionary of metaclass info.
        metaclass_to_classname = self._metaclass_to_classname_builder.build(bad_metaclass, bad_classname)
        for metaclass, classname in metaclass_to_classname.items():
            meta_superclass = self._metaclass_to_meta_superclass[metaclass]
            superclass_name = metaclass_to_classname.get(meta_superclass, None)
            self._metaclass_info[metaclass] = class_info.ClassInfo(classname, metaclass, None, None,
                                                                   self._metaclass_to_class_size[metaclass],
                                                                   superclass_name,
                                                                   meta_superclass)

    def _collect_metaclasses_by_ctor_xrefs(self):
        """
        """
        OSObject_str = next(s for s in idautils.Strings() if str(s) == "OSObject")
        if not OSObject_str:
            raise PhaseException("Couldn't find OSObject str")

        OSObject_xref = ida_xref.get_first_dref_to(OSObject_str.ea)

        # Decompile the method using hexrays
        cfunc = ida_hexrays.decompile(OSObject_xref)
        if cfunc is None:
            raise PhaseException("cfunc not found, did IDA finish processing the kernel yet? Let it finish and retry.")

        call_insn = get_call_from_insn(cfunc.get_eamap()[OSObject_xref][0])
        if not call_insn or call_insn.a[1].obj_ea != OSObject_str.ea:
            raise PhaseException("Param 1 isnt obj_ea")

        OSMetaClass_ctor = call_insn.x.obj_ea
        for xref in idautils.XrefsTo(OSMetaClass_ctor):
            # TODO: this used to be in try...except, why though?
            self.parse_OSMetaClass_ctor_xref(xref.frm)

    def parse_OSMetaClass_ctor_xref(self, ea):
        cfunc = ida_hexrays.decompile(ea)
        call_insn = get_call_from_insn(cfunc.get_eamap()[ea][0])
        if not call_insn:
            return
        metaclass = dref_cast_and_ref_to_obj(call_insn.a[0])
        classname_ea = dref_cast_and_ref_to_obj(call_insn.a[1])
        super_metaclass = dref_cast_and_ref_to_obj(call_insn.a[2], dref_obj=True) or 0
        class_size_arg = call_insn.a[3]
        if not (metaclass and classname_ea and class_size_arg.op == ida_hexrays.cot_num):
            return
        if re.match(".*__cstring", idc.get_segm_name(classname_ea)) and idc.get_segm_name(metaclass):
            self._found_metaclass(metaclass,
                                  idc.get_strlit_contents(classname_ea).decode(),
                                  class_size_arg.numval(),
                                  super_metaclass)

    def _collect_metaclasses_from_init_func_sections(self):
        """
        Process a __mod_init_func section for OSMetaClass information.
        """
        for segstart in idautils.Segments():
            segname = idc.get_segm_name(segstart)
            segend = idc.get_segm_end(segstart)

            # Filter the segments that we should process according to their name
            if not (re.match('.*__mod_init_func', segname) or re.match('.*__kmod_init', segname)):
                continue

            self.log(2, 'Processing segment {}', segname)
            for func in idau.ReadWords(segstart, segend):
                self._process_mod_init_func_for_metaclasses(func)

    def _process_mod_init_func_for_metaclasses(self, func):
        """
        Process a single function from the __mod_init_func section for OSMetaClass information.
        """
        self.log(4, 'Processing function {}', idc.get_func_name(func))

        def on_BL(addr, reg):
            X0, X1, X3 = reg['X0'], reg['X1'], reg['X3']
            if not (X0 and X1 and X3):
                return
            self.log(5, 'Have call to {:#x}({:#x}, {:#x}, ?, {:#x})', addr, X0, X1, X3)

            # OSMetaClass::OSMetaClass(this, className, superclass, classSize)
            if re.match(".*__cstring", idc.get_segm_name(X1)) and idc.get_segm_name(X0):
                # Register this metaclass in the dictionary
                self._found_metaclass(X0, idc.get_strlit_contents(X1).decode(), X3, reg['X2'] or None)

        emulate_arm64(func, idc.find_func_end(func), on_BL=on_BL)


def get_call_from_expr(expr):
    if expr.op == ida_hexrays.cot_cast:
        expr = expr.x
    if expr.op == ida_hexrays.cot_call:
        return expr
    return None


def get_call_from_insn(insn):
    # TODO: move to ida_utilities.py
    if type(insn) == ida_hexrays.cinsn_t and insn.op == ida_hexrays.cit_expr:
        expr = insn.cexpr
    elif type(insn) == ida_hexrays.cexpr_t:
        expr = insn
    else:
        return None
    if expr.op == ida_hexrays.cot_asg:
        # For the form of: var = call(...)
        call_asg_y = get_call_from_expr(expr.y)
        if call_asg_y:
            return call_asg_y
        # For the form of: *call(...) = .... or call(...)->__vftable = ...
        if expr.x.op == ida_hexrays.cot_ptr or expr.x.op == ida_hexrays.cot_memptr:
            call_asg_x = get_call_from_expr(expr.x.x)
            if call_asg_x:
                return call_asg_x
    else:
        return get_call_from_expr(expr)
    return None


def dref_cast_and_ref_to_obj(expr, dref_obj=False):
    found_ref = False
    if expr.op == ida_hexrays.cot_cast:
        expr = expr.x
    if expr.op == ida_hexrays.cot_ref:
        expr = expr.x
        found_ref = True
    if expr.op != ida_hexrays.cot_obj:
        return None
    if not found_ref and dref_obj:
        return idau.read_ptr(expr.obj_ea)
    return expr.obj_ea

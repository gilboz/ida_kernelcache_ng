from .base_phase import BasePhase
import ida_kernelcache.ida_utilities as idau
from ida_kernelcache.symbol import metaclass_symbol_for_class


class AddMetaClassSymbols(BasePhase):
    """
    Populate IDA with OSMetaClass instance symbols for an iOS kernelcache.

    Search through the kernelcache for OSMetaClass instances and add a symbol for each known
    instance.
    """

    def run(self):
        for classname, classinfo in self._kc.classes.items():
            if classinfo.metaclass:
                self.log(1, 'Class {} has OSMetaClass instance at {:#x}', classname, classinfo.metaclass)
                if not self._add_metaclass_symbol(classinfo.metaclass, classname):
                    self.log(0, 'Could not add metaclass symbol for class {} at address {:#x}', classname,
                             classinfo.metaclass)
            else:
                self.log(1, 'Class {} has no known OSMetaClass instance', classname)

    def _add_metaclass_symbol(self, metaclass, classname):
        """
        Add a symbol for the OSMetaClass instance at the specified address.

        Arguments:
            metaclass: The address of the OSMetaClass instance.
            classname: The name of the C++ class with this OSMetaClass instance.

        Returns:
            True if the OSMetaClass instance's symbol was created successfully.
        """
        metaclass_symbol = metaclass_symbol_for_class(classname)
        if not idau.set_ea_name(metaclass, metaclass_symbol):
            self.log(0, 'Address {:#x} already has name {} instead of OSMetaClass instance symbol {}'
                     .format(metaclass, idau.get_ea_name(metaclass), metaclass_symbol))
            return False
        return True

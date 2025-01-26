"""
PacSymbolicate
An effective method to symbolicate virtual methods in the kernelcache

We have three main goals:
    1. Set a nice name for the vmethod.
    2. Edit the signature of the function at vmethod_ea
    3. Set the name and signature of the vtable entry in the respective *_vtbl structure

    // void (__fastcall *func)(ATest *__hidden this, int a, int b);
"""
import itertools
import json
import pathlib
from typing import TYPE_CHECKING

from ida_kernelcache import symbols
from ida_kernelcache.exceptions import PhaseException
from ida_kernelcache.ida_helpers import names
from ida_kernelcache import rtti
from .base_phase import BasePhase

if TYPE_CHECKING:
    from ida_kernelcache.rtti import ClassInfo, VtableEntry


class PacSymbolicate(BasePhase):
    SYMBOLS_DB_PATH = pathlib.Path(__file__).parent.parent.parent / 'symdb.json'

    def __init__(self, kc):
        super().__init__(kc)

        self.num_total_vtable_entries = 0

        self.num_overrides = 0
        self.num_added = 0
        self.num_invalid = 0

        if not self.SYMBOLS_DB_PATH.is_file():
            raise PhaseException(f'{self.SYMBOLS_DB_PATH} does not exist!')

        with self.SYMBOLS_DB_PATH.open('r') as db_file:
            tmp_db: dict[str, dict[str, str]] = json.load(db_file)

        # JSON format does not let me encode keys as integers, so I perform this transformation after loading it so PAC diversifiers can be looked up as integers
        self.sym_db = {}
        for class_name, pac_dict in tmp_db.items():
            self.sym_db[class_name] = {int(pac_str, 16): mangled_symbol for pac_str, mangled_symbol in pac_dict.items()}

    def run(self):
        num_symbolicated_before = self._kc.vmethod_info_map.num_symbolicated
        # Perform a BFS scan over the inheritance tree for all classes with vtable information
        for class_info in self._kc.class_info_map.bfs(must_have_vtable=True):

            # Iterate over the entries in the current vtable entries
            for vtable_entry in class_info.vtable_info.entries:

                self.num_total_vtable_entries += 1

                # Skip vtable entries that point to a vmethod that is already symbolicated
                # Because we are performing a BFS scan, inherited vmethods are already handled on previous iterations, there is nothing to do here.
                # Nothing to symbolicate for pure virtual methods
                if vtable_entry.vmethod_info.mangled_symbol or vtable_entry.inherited or vtable_entry.pure_virtual:
                    continue

                # TODO: Ideally, we should have 0 invalid vtable entries. We must fix the function boundaries earlier
                if vtable_entry.vmethod_info.func is None:
                    self.num_invalid += 1

                mangled_symbol = self._resolve_vmethod_info(class_info, vtable_entry)

                # Set the function name!
                if mangled_symbol:
                    vtable_entry.vmethod_info.mangled_symbol = mangled_symbol
                    vtable_entry.vmethod_info.symbol_source = rtti.SymbolSource.PAC_DB

                    demangled_symbol = names.demangle(mangled_symbol)
                    self.log.debug(f'{vtable_entry.vmethod_ea:#x} {demangled_symbol} '
                                  f'o:{int(vtable_entry.overrides)} '
                                  f'i:{int(vtable_entry.inherited)} '
                                  f'pv:{int(vtable_entry.pure_virtual)} '
                                  f'a:{int(vtable_entry.added)}')

        num_not_symbolicated = len(self._kc.vmethod_info_map) - self._kc.vmethod_info_map.num_symbolicated

        self.log.info(f'{self.num_total_vtable_entries} total vtable entries (multiple may point to the same vmethod)')
        self.log.info(f'o:{self.num_overrides} a:{self.num_added}')
        self.log.info(f'{self.num_invalid} invalid vmethods were detected')
        self.log.info(f'before:{num_symbolicated_before} after:{self._kc.vmethod_info_map.num_symbolicated} not:{num_not_symbolicated}')

    def _resolve_vmethod_info(self, class_info: 'ClassInfo', vtable_entry: 'VtableEntry') -> str | None:
        """
        Given a vtable entry and class information, we try to find a matching mangled symbol from the symbols database.
        In case a match is found we return the mangled name.
        """

        if vtable_entry.added:
            return self._handle_added(class_info, vtable_entry)

        if vtable_entry.overrides:
            return self._handle_overrides(class_info, vtable_entry)

        raise PhaseException(f'Invalid vtable entry state {class_info.class_name} index:{vtable_entry.index}')

    def _lookup_db(self, class_name: str, pac_diversifier: int) -> str | None:
        pac_dict = self.sym_db.get(class_name, {})
        return pac_dict.get(pac_diversifier, None)

    def _handle_added(self, origin_class_info: 'ClassInfo', vtable_entry: 'VtableEntry') -> str | None:
        """
        If the vtable entry was added in this current class we search the symbols db. Unfortunately, in case we don't find a match, we don't have information about this vmethod
        So we use some generic class_name::vmethod_{i} template. We may use the "guess type" functionality of IDA but it is far from accurate.

        Searching the descendants adds ~100 symbols
        """

        for class_info in origin_class_info.descendants(inclusive=True):
            mangled_symbol = self._lookup_db(class_info.class_name, vtable_entry.pac_diversifier)
            if mangled_symbol:
                self.num_added += 1

                # In case we were able to resolve through superclass pac dict then
                # must adjust the classname of the symbol to fit the current class
                if class_info != origin_class_info:
                    return symbols.sub_classname(mangled_symbol, origin_class_info.class_name)
                return mangled_symbol

    def _handle_overrides(self, origin_class_info: 'ClassInfo', vtable_entry: 'VtableEntry') -> str | None:
        # Search the entire inheritance branch
        for class_info in itertools.chain(origin_class_info.ancestors(True), origin_class_info.descendants(inclusive=False)):
            mangled_symbol = self._lookup_db(class_info.class_name, vtable_entry.pac_diversifier)
            if mangled_symbol:
                self.num_overrides += 1

                # In case we were able to resolve through superclass pac dict then
                # must adjust the classname of the symbol to fit the current class
                if class_info != origin_class_info:
                    return symbols.sub_classname(mangled_symbol, origin_class_info.class_name)
                return mangled_symbol

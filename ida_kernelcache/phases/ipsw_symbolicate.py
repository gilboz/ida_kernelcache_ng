import json
import pathlib

import ida_kernwin
import ida_nalt

from ida_kernelcache import symbols, rtti
from ida_kernelcache.ida_helpers import names
from .base_phase import BasePhase


class IPSWSymbolicate(BasePhase):
    IPSW_DB_SUFFIX = '.symbols.json'

    def __init__(self, kc):
        super().__init__(kc)

        self.ipsw_symbols_db: dict[int, str] = {}

        # Search for the ipsw symbolicate database which is stored near kernelcache with a known suffix
        ipsw_db_path = pathlib.Path(ida_nalt.get_input_file_path() + self.IPSW_DB_SUFFIX)
        # bin_file = ida_loader.get_path(ida_loader.PATH_TYPE_CMD)
        # ipsw_db_path = pathlib.Path(bin_file + self.IPSW_DB_SUFFIX)
        self.log.info(f'Searching for IPSW symbols DB at {ipsw_db_path}')
        if not ipsw_db_path.exists():
            user_path = ida_kernwin.ask_file(0, 'IPSW Symbols DB|*.symbols.json', 'Enter the IPSW Symbols File')
            if user_path is None:
                return
            ipsw_db_path = pathlib.Path(user_path)

        with ipsw_db_path.open('r') as db_file:
            tmp_db: dict[str, str] = json.load(db_file)
        self.ipsw_symbols_db = {int(ea_str, 10): sym for ea_str, sym in tmp_db.items()}
        self.log.info(f'Loaded {len(self.ipsw_symbols_db)} symbols from IPSW symbols DB at {ipsw_db_path}')

    def run(self):
        if not self.ipsw_symbols_db:
            self.log.warning('Skipping IPSW Symbol propagation')
            return

        self._symbolicate_vmethods()
        # self._propagate_symbols()

    def _symbolicate_vmethods(self):
        num_symbolicated = 0
        for vmethod_info in self._kc.vmethod_info_map.values():

            # Skip already symbolicated
            if vmethod_info.mangled_symbol:
                continue

            # Search the vmethod ea in the ipsw symbols database
            if vmethod_info.vmethod_ea in self.ipsw_symbols_db:
                if vmethod_info.vmethod_ea == rtti.VtableInfo.CXA_PURE_VIRTUAL_EA:
                    continue

                mangled_symbol = self.ipsw_symbols_db[vmethod_info.vmethod_ea]

                if not mangled_symbol.startswith('__ZN'):
                    self.log.error(f'{mangled_symbol} symbol for vmethod at {vmethod_info.vmethod_ea:#x} is not a valid nested name symbol!')
                    continue
                vmethod_info.mangled_symbol = mangled_symbol
                vmethod_info.symbol_source = rtti.SymbolSource.IPSW_DB
                num_symbolicated += 1

        self.log.info(f'symbolicated:{num_symbolicated} vmethods from IPSW_DB')

    def _propagate_symbols(self):
        """
        TODO: debug and see if this stage is useful
        """
        num_propagated = 0
        # Perform a BFS scan over the inheritance tree for all classes with vtable information
        for class_info in self._kc.class_info_map.bfs(must_have_vtable=True):
            for vtable_entry in class_info.vtable_info.entries:

                # Skip non-symbolicated vmethods or non-relevant virtual methods
                if vtable_entry.vmethod_info.mangled_symbol is None or vtable_entry.pure_virtual or vtable_entry.inherited:
                    continue

                # Propagate the vmethod symbol from added/overridden vtable entries to related vtable entries
                for related_class_info, related_entry in class_info.vtable_info.related_entries(vtable_entry):

                    # Skip related entries that are already symbolicated!
                    if related_entry.vmethod_info.mangled_symbol:
                        continue

                    if vtable_entry.vmethod_info.symbol_source == rtti.SymbolSource.PAC_DB:
                        if related_entry.pac_diversifier != vtable_entry.pac_diversifier:
                            self.log.error(
                                f'Propagated PAC_DB symbol but pac diverisifiers are not equal! src:{vtable_entry.pac_diversifier:#} dst:{related_entry.pac_diversifier:#x}')
                            self.log.info(vtable_entry)
                            self.log.info(related_entry)

                    propagated_symbol = symbols.sub_classname(vtable_entry.vmethod_info.mangled_symbol, related_class_info.class_name)
                    self.log.info(f'Propagated {names.demangle(vtable_entry.vmethod_info.mangled_symbol)} --> {names.demangle(propagated_symbol)}')
                    related_entry.vmethod_info.mangled_symbol = propagated_symbol
                    related_entry.vmethod_info.symbol_source = rtti.SymbolSource.PROPAGATION
                    num_propagated += 1
        self.log.info(f'symbolicated:{num_propagated} vmethods from SYMBOL_PROPAGATION')

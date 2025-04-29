import collections
import dataclasses
import functools
import json
import enum
import pathlib
import re

import lief
import lief.logging
import pac

KDK_DIR = pathlib.Path('/Library/Developer/KDKs/KDK_15.4_24E248.kdk')
EXTENSIONS_DIR = KDK_DIR / 'System/Library/Extensions'
KERNELS_DIR = KDK_DIR / 'System/Library/Kernels'
EXTENSIONS_GLOB = '*.kext/Contents/MacOS/*'
KERNELS_GLOB = 'kernel.release.t????'  # Avoid vmapple and .dSYM directories
OUT_FILE = pathlib.Path('/tmp/symdb.json')
TRASH_FILE = pathlib.Path('/tmp/random.json')
MANGLED_PREFIX = '__Z'
METHOD_PREFIX = '__ZN'


class Flags(enum.IntEnum):
    N_SECT = 0x0e
    N_STAB = 0xe0
    N_TYPE = 0x0e
    N_EXT = 0x01


@dataclasses.dataclass
class SymbolInfo:
    mangled: str
    class_name: str
    pac: int

    def __init__(self, mangled: str):
        self.mangled = mangled
        self.class_name = get_classname(mangled)
        self.pac = pac.cxx_compute_pac(mangled)

    def __hash__(self):
        return hash(self.mangled)

    def __eq__(self, other):
        return self.mangled == other.mangled


@dataclasses.dataclass
class ExtractionStats:
    empty: int
    errors: int
    non_mangled: set[str]
    total_syms: set[str]
    skipped: set[str]
    nested_names: set[SymbolInfo]


CLASSNAME_PATTERN = re.compile(r'__ZN([rVK]?)([RO]?)(\d+)(.+)', flags=re.IGNORECASE)


def get_classname(mangled_symbol: str) -> str:
    mo = CLASSNAME_PATTERN.match(mangled_symbol)
    if mo is None:
        raise ValueError(f'{mangled_symbol} does not match pattern..')
    len = int(mo.group(3))
    return mo.group(4)[:len]


def extract_syms(file_path: pathlib.Path):
    macho = lief.parse(file_path)
    print(f'[✅] {file_path.name} has {len(macho.symbols)} symbols!')
    for sym in macho.symbols:

        # Skip empty symbols (why do they exist in the first place?)
        if sym.name == '':
            stats.empty += 1
            continue

        # Copied from iometa
        if sym.raw_type & Flags.N_TYPE != Flags.N_SECT or (sym.raw_type & Flags.N_STAB and not (sym.raw_type & Flags.N_EXT)):
            # print(f'Skipping {sym.name} with type {sym.type:#x}')
            stats.skipped.add(sym.name)
            continue

        if not sym.name.startswith('__Z'):
            stats.non_mangled.add(sym.name)
            continue

        # nested-names per the Itanium CXX ABI start with N they also must end with E?
        if sym.name.startswith(METHOD_PREFIX):
            try:
                sym_info = SymbolInfo(sym.name)
            except ValueError:
                stats.errors += 1
                continue
            stats.nested_names.add(sym_info)
        else:
            stats.total_syms.add(sym.name)


def handle_extensions():
    extensions: list[pathlib.Path] = list(EXTENSIONS_DIR.glob(EXTENSIONS_GLOB))
    print(f'[✅] Found {len(extensions)} kexts')

    for kext in extensions:
        extract_syms(kext)


def handle_kernels():
    kernels: list[pathlib.Path] = list(KERNELS_DIR.glob(KERNELS_GLOB))
    for kernel in kernels:
        print(f'[✅] Extracting symbols from {kernel.name}')
        extract_syms(kernel)


stats = ExtractionStats(0, 0, set(), set(), set(), set())


def main():
    if not KDK_DIR.is_dir():
        print(f'[❌] {KDK_DIR} does not exit')
        return 1

    if not EXTENSIONS_DIR.is_dir():
        print(f'[❌] {EXTENSIONS_DIR} does not exit')
        return 1

    lief.logging.set_level(lief.logging.LEVEL.CRITICAL)
    handle_kernels()
    handle_extensions()
    if stats.errors:
        print(f'[❌] Errors {stats.errors}')
    print(f'[✅] Empty {stats.empty}')
    print(f'[✅] Skipped {len(stats.skipped)}')
    print(f'[✅] Dropped {len(stats.non_mangled)} non mangled symbols')
    print(f'[✅] Found a total of {len(stats.nested_names)} methods')
    print(f'[✅] Scraped a total {len(stats.total_syms)} non-nested mangled symbols!')

    # A hack to make accesses to db['class_name']['pac'] to always work!
    partial = functools.partial(collections.defaultdict, list)
    db = collections.defaultdict(partial)

    f = OUT_FILE.open('w')
    for sym_info in stats.nested_names:
        db[sym_info.class_name][f'{sym_info.pac:#x}'] = sym_info.mangled
        # f.write(f'{sym_info.pac:#06x} {sym_info.class_name:40s} {sym_info.mangled}\n')
    json.dump(db, f, indent=4)
    f.close()

    f = TRASH_FILE.open('w')
    f.write('\n'.join(stats.total_syms))
    f.close()


if __name__ == '__main__':
    main()

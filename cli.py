import argparse
import pathlib

# TODO: importing idapro seems to alternate the PYTHONPATH making other imports to stop working which is very annoying
import idapro

import sys
import os
# sys.path.insert(0, os.path.dirname(__file__))
from ida_kernelcache.kernelcache import KernelCache


class IDBOpenError(Exception):
    pass


MACHO_MAGIC = b'\xcf\xfa\xed\xfe'
IDB_MAGIC = b'IDA2'
IDB_SUFFIXES = {'.i64'}


def main(args: argparse.Namespace):
    if args.idb:
        print(f'Opening IDB {args.idb}')
        file_path = str(args.idb)
    else:  # must be that the user chose --kc
        print(f'Opening kernelcache file {args.kc}')
        file_path = str(args.kc)

    if args.enable_console_messages:
        idapro.enable_console_messages(True)

    err = idapro.open_database(file_path, run_auto_analysis=args.run_auto_analysis)
    if err:
        raise IDBOpenError(f'open_database failed: {err}')
    try:
        kc = KernelCache()
        kc.process()
        kc.rtti_db.save()
    finally:
        idapro.close_database()


def kernelcache_file(kc_path_arg: str) -> pathlib.Path:
    kc_path = pathlib.Path(kc_path_arg)
    if not kc_path.is_file():
        raise argparse.ArgumentTypeError(f'{kc_path} does not exist or its not a file!')

    with kc_path.open('rb') as kc_file:
        magic = kc_file.read(4)

    if magic != MACHO_MAGIC:
        raise argparse.ArgumentTypeError(f'{kc_path} is not a Mach-O!')
    return kc_path


def idb_file(idb_path_arg: str) -> pathlib.Path:
    idb_path = pathlib.Path(idb_path_arg)

    if not idb_path.is_file():
        raise argparse.ArgumentTypeError(f'{idb_path} does not exist or its not a file!')

    if idb_path.suffix not in IDB_SUFFIXES:
        raise argparse.ArgumentTypeError(f'{idb_path} unexpected suffix! expected:{IDB_SUFFIXES}')

    with idb_path.open('rb') as kc_file:
        magic = kc_file.read(4)
    if magic != IDB_MAGIC:
        raise argparse.ArgumentTypeError(f'{idb_path} is not an IDB!')
    return idb_path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="choose one of --idb or --kc")

    input_file_group = parser.add_mutually_exclusive_group(required=True)
    input_file_group.add_argument('--idb', help='Path to IDB (*.i64)', type=idb_file)
    input_file_group.add_argument('--kc', help='Path to KernelCache', type=kernelcache_file)

    optionals = parser.add_argument_group(title='Optional arguments')
    optionals.add_argument('--no-auto-analysis', help='For IDB (.i64) input files, do not auto-analyze',
                           action='store_false', dest='run_auto_analysis')
    optionals.add_argument('--enable-console-messages', help='Enable IDA console messages (not really recommended)', action='store_true')

    args = parser.parse_args()

    if not args.run_auto_analysis and args.kc:
        parser.error('when passing --kc you cannot pass --no-auto-analysis')
    main(args)

import argparse
import pathlib

import idapro

import sys
import os
# sys.path.insert(0, os.path.dirname(__file__))
from ida_kernelcache.kernelcache import KernelCache


class IDBOpenError(Exception):
    pass


def main(db_path: pathlib.Path, load: bool):
    print(f'Opening DB {db_path}')
    err = idapro.open_database(str(db_path), run_auto_analysis=False)
    if err:
        raise IDBOpenError(f'open_database failed: {err}')
    try:
        kc = KernelCache(load=load)
        kc.process()
        kc.rtti_db.save()
    finally:
        idapro.close_database()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('db_path', help='Path to IDB', type=pathlib.Path)
    parser.add_argument('--no-load', help='Do not load rtti_db.json', action='store_false', dest='load')
    args = parser.parse_args()
    main(args.db_path, args.load)

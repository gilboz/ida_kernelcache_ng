import idapro
import ida_kernelcache.kernelcache as kernelcache
from ida_kernelcache.phases.collect_classes import CollectClasses
from ida_kernelcache.phases.collect_vtables import CollectVtables
import json
import pickle
import os

DB_PATH = r'./kernelcache_testing.i64'


def main():
    print(f'Opening DB {DB_PATH}')
    err = idapro.open_database(DB_PATH, run_auto_analysis=False)
    if err:
        print(f'Failed opening DB..')
        exit(1)

    kc = kernelcache.KernelCache()

    phases = [CollectClasses, CollectVtables]
    kc.process(phases=phases)

    idapro.close_database()


if __name__ == '__main__':
    main()

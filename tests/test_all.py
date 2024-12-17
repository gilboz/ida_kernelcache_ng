import idapro

import ida_kernelcache.kernelcache as kernelcache

DB_PATH = r'./kernelcache_testing.i64'


def main():
    print(f'Opening DB {DB_PATH}')
    err = idapro.open_database(DB_PATH, run_auto_analysis=False)
    if err:
        print(f'Failed opening DB..')
        exit(1)

    kc = kernelcache.KernelCache()
    kc.process()

    idapro.close_database()


if __name__ == '__main__':
    main()

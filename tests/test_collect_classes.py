import idapro
import ida_kernelcache.kernelcache as kernelcache
import ida_kernelcache.phases

DB_PATH = r'./kernelcache_testing.i64'


def main():
    print('Opening DB')
    err = idapro.open_database(DB_PATH, run_auto_analysis=False)
    if err:
        print(f'Failed opening DB..')
        exit(1)

    kc = kernelcache.KernelCache()
    kc.process(phases=[ida_kernelcache.phases.CollectClasses])

    print(f'Found a total of {len(kc.class_info_map)}')
    idapro.close_database()


if __name__ == '__main__':
    main()

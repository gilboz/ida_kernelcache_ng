from test_utils import get_kc, groupby_segment
import ida_kernelcache.phases

DB_PATH = r'./kernelcache_testing.i64'


def main():
    with get_kc(load=False) as kc:
        kc.process(phases=[ida_kernelcache.phases.CollectClasses])
        print(f'Found a total of {len(kc.class_info_map)}')
        groupby_segment(kc)



if __name__ == '__main__':
    main()

import idapro

from test_utils import get_kc, groupby_segment, dump_inheritance
from ida_kernelcache.phases.collect_classes import CollectClasses
from ida_kernelcache.phases.collect_vtables import CollectVtables

DB_PATH = r'./kernelcache_testing.i64'


def main():
    with get_kc(load=False) as kc:
        kc.process(phases=[CollectClasses, CollectVtables])
        print(f'There are a total of {len(kc.vmethod_info_map)} vmethods globally!')
        # segment_classes = groupby_segment(kc)
        # dump_inheritance(kc, set(segment_classes['com.apple.AGXG14P:__bss']))


if __name__ == '__main__':
    main()

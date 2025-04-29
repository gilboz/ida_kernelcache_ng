from test_utils import get_kc, dump_inheritance
from ida_kernelcache.phases.collect_classes import CollectClasses
from ida_kernelcache.phases.collect_vtables import CollectVtables

DB_PATH = r'./kernelcache_testing.i64'


def lookup_pure_virtual(kc):
    for class_info in kc.class_info_map.bfs(must_have_vtable=True):
        for vtable_entry in class_info.vtable_info.entries:
            if vtable_entry.pure_virtual:
                print(
                    f'{class_info.class_name} {vtable_entry.entry_ea:#x} {vtable_entry.pac_diversifier:#x} a={int(vtable_entry.added)} o={int(vtable_entry.overrides)} i={int(vtable_entry.inherited)}')


def dump_osobject_vtable(kc):
    osobject_class_info = kc.class_info_map['OSObject']
    print(osobject_class_info.vtable_info)
    for vtable_entry in osobject_class_info.vtable_info.entries:
        print(vtable_entry)


def main():
    with get_kc(load=False) as kc:
        kc.process(phases=[CollectClasses, CollectVtables])
        print(f'There are a total of {len(kc.vmethod_info_map)} vmethods globally!')
        lookup_pure_virtual(kc)
        dump_osobject_vtable(kc)
        # dump_inheritance(kc, set(segment_classes['com.apple.AGXG14P:__bss']))


if __name__ == '__main__':
    main()

import contextlib

import idapro

from ida_kernelcache import rtti
import ida_kernelcache.kernelcache as kernelcache

DB_PATH = r'./kernelcache_testing.i64'


class IDBOpenError(Exception):
    pass


@contextlib.contextmanager
def get_kc(load: bool = True):
    print(f'Opening DB {DB_PATH}')
    try:
        err = idapro.open_database(DB_PATH, run_auto_analysis=False)
        if err:
            raise IDBOpenError(f'Failed opening DB..')
        kc = kernelcache.KernelCache(load=load)
        yield kc
        kc.rtti_db.save()
    finally:
        idapro.close_database()


def groupby_segment(kc) -> dict[str, list[rtti.ClassInfo]]:
    # counters = {kext.name: 0 for kext in kc.kexts}
    counters = {segment.name: [] for segment in kc.segments_list}
    for class_info in kc.class_info_map.values():
        # kext = kc.get_ea_kext(class_info.metaclass_ea)
        for segment in kc.segments_list:
            if segment.start_ea <= class_info.metaclass_ea <= segment.end_ea:
                counters[segment.name].append(class_info)
                break
        else:
            print(f'{class_info.class_name} not found in any kext {class_info.metaclass_ea:#x}!')

    # Generate a list of tuples and drop 0 counter segments
    counters_list = [(t[0], len(t[1])) for t in counters.items() if t[1]]
    counters_list.sort(key=lambda t: t[1], reverse=True)
    for segment_name, counter in counters_list:
        print(f'{segment_name}: {counter}')

    return counters


def dump_inheritance(kc, classes_whitelist: set[rtti.ClassInfo]):
    with open(r'/tmp/rtti', 'w') as f:
        f.write('---\n')
        f.write('title: Inheritance Diagram\n')
        f.write('---\n')
        f.write('flowchart TD\n')
        f.write('classDef optimized fill:#f44336;\n')

        subtree = rtti.ClassInfoMap()
        for class_info in classes_whitelist:
            for ancestor in class_info.ancestors(inclusive=True):
                subtree.add_classinfo(ancestor)

        print(f'{len(classes_whitelist)} turned into a subtree of {len(subtree)} nodes')
        for class_info in subtree.bfs(must_have_vtable=False):
            if class_info.metaclass_ea in subtree:
                print(class_info)
                if class_info.is_subclass():
                    depth = 2
                    if 5 < len(class_info.superclass.subclasses) < 10:
                        depth = 3
                    elif len(class_info.superclass.subclasses) >= 10:
                        depth = 4
                    f.write(f'    {class_info.superclass.class_name} {"-" * depth}> {class_info.class_name}{":::optimized" if class_info.optimized else ""}\n')

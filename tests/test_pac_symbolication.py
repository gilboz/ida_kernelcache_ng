from test_utils import get_kc
from ida_kernelcache.phases import CollectVtables, CollectClasses
from ida_kernelcache.phases.pac_symbolicate import PacSymbolicate



def main():
    with get_kc(load=False) as kc:
        phases = [CollectClasses, CollectVtables, PacSymbolicate]
        kc.process(phases=phases)


if __name__ == '__main__':
    main()

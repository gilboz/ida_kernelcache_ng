from test_utils import get_kc

from ida_kernelcache.phases.collect_classes import CollectClasses
from ida_kernelcache.phases.collect_vtables import CollectVtables
from ida_kernelcache.phases.pac_symbolicate import PacSymbolicate
from ida_kernelcache.phases.ipsw_symbolicate import IPSWSymbolicate
from ida_kernelcache.phases import ApplyRTTIInfoPhase


def main():
    with get_kc() as kc:
        phases = [CollectClasses, CollectVtables, PacSymbolicate, IPSWSymbolicate, ApplyRTTIInfoPhase]
        kc.process(phases=phases)


if __name__ == '__main__':
    main()

from test_utils import get_kc

from ida_kernelcache.phases.create_types import CreateTypes
from ida_kernelcache.phases.ipsw_symbolicate import IPSWSymbolicate
from ida_kernelcache.phases.pac_symbolicate import PacSymbolicate


def main():
    with get_kc(load=True) as kc:
        kc.process(phases=[PacSymbolicate, IPSWSymbolicate, CreateTypes])


if __name__ == '__main__':
    main()

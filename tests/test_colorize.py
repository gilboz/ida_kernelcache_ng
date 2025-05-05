from test_utils import get_kc
from ida_kernelcache.phases import ColorizeVtables


def main():
    with get_kc(load=True) as kc:
        kc.process(phases=[ColorizeVtables])


if __name__ == '__main__':
    main()

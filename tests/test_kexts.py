from test_utils import get_kc


def main():
    with get_kc() as kc:
        print(kc.kexts[:4])
        kc.kexts.sort()
        print(kc.kexts[:4])


if __name__ == '__main__':
    main()

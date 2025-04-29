import argparse
import struct

import dataclasses

MASk64 = 0xffffffffffffffff


def rotl(x, b):
    """Rotate left (ROTL) operation for 64-bit integers."""
    return ((x << b) & MASk64) | (x >> (64 - b))


@dataclasses.dataclass
class HashState:
    v0: int
    v1: int
    v2: int
    v3: int

    def __repr__(self):
        return f'{self.v0:#x} {self.v1:#x} {self.v2:#x} {self.v3:#x}'


def siphash(data):
    """Python implementation of the siphash function."""

    # These magic values were taken from: https://github.com/Siguza/iometa/blob/master/src/cxx.c#L37
    # These are probably Apple specific - where did Siguza get them from?
    #
    state = HashState(v0=0x0a257d1c9bbab1c0, v1=0xb0eef52375ef8302, v2=0x1533771c85aca6d4, v3=0xa0e4e32062ff891c)

    def SIPROUND(iterations=1):
        for _ in range(iterations):
            state.v0 = (state.v0 + state.v1) & MASk64  # Wrap 64 bit integers
            state.v1 = rotl(state.v1, 13) ^ state.v0
            state.v0 = rotl(state.v0, 32)
            state.v2 = (state.v2 + state.v3) & MASk64  # Wrap 64 bit integers
            state.v3 = rotl(state.v3, 16) ^ state.v2
            state.v0 = (state.v0 + state.v3) & MASk64  # Wrap 64 bit integers
            state.v3 = rotl(state.v3, 21) ^ state.v0
            state.v2 = (state.v2 + state.v1) & MASk64  # Wrap 64 bit integers
            state.v1 = rotl(state.v1, 17) ^ state.v2
            state.v2 = rotl(state.v2, 32)

    # Process 8-byte chunks
    for i in range(0, len(data) & ~7, 8):
        m = struct.unpack('<Q', data[i:i + 8])[0]
        state.v3 ^= m
        SIPROUND(2)
        state.v0 ^= m

    # Process remaining bytes
    b = len(data) << 56
    rem = len(data) & 7
    b |= int.from_bytes(data[-rem:], 'little')
    state.v3 ^= b
    SIPROUND(2)

    state.v0 ^= b

    # Finalization
    state.v2 ^= 0xff
    SIPROUND(4)
    return state.v0 ^ state.v1 ^ state.v2 ^ state.v3


def cxx_compute_pac(symbol):
    """Compute PAC value for a symbol."""
    if not symbol.startswith("_"):
        raise ValueError('Invalid symbol!')

    symbol = symbol[1:]  # Remove leading '_'

    # Ignore vendor-specific suffix
    if '.' in symbol:
        symbol = symbol.split('.', 1)[0]

    symbol_data = symbol.encode("ascii")
    siphash_result = siphash(symbol_data)
    pac = (siphash_result % 0xffff) + 1
    return pac


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('symbol', help='Mangled symbol')
    args = parser.parse_args()
    pac = cxx_compute_pac(args.symbol)
    print(f'PAC: {pac:#x}')


if __name__ == '__main__':
    main()

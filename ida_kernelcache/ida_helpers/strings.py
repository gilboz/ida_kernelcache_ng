import functools
import idautils

from ida_kernelcache.exceptions import StringNotFoundError

CACHED_STRINGS: idautils.Strings | None = None


def strings_accessor(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        global CACHED_STRINGS
        if CACHED_STRINGS is None:
            CACHED_STRINGS = idautils.Strings()
        return func(*args, **kwargs)

    return wrapper


@strings_accessor
def find_str(target: str) -> idautils.Strings.StringItem:
    try:
        return next(s for s in idautils.Strings() if str(s) == target)
    except StopIteration:
        raise StringNotFoundError(f'Could not find string {target}')

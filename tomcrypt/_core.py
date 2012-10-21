import ctypes

from . import meta


class _CTypesWrapper(object):
    
    def __getattr__(self, name):
        obj = (getattr(ctypes, name, None) or
               getattr(ctypes, "c_" + name, None)
        )
        if obj is not None:
            setattr(self, name, obj)
        return obj

C = _CTypesWrapper()


# Import the module, and get a ctypes library for it.
ltc_mod = __import__(meta.module_name, fromlist=['c'])
ltc = ctypes.CDLL(ltc_mod.__file__)


def wrapper(restype, *argtypes):
    def _wrapper(func):
        c_func = getattr(ltc, func.__name__)
        c_func.restype = restype
        c_func.argtypes = argtypes
        def _wrapped(*args, **kwargs):
            return func(c_func, *args, **kwargs)
        return _wrapped
    return _wrapper


@wrapper(C.char_p, C.int)
def error_to_string(func, errno):
    # We need to deal with libtomcrypt not defining this error message.
    if errno == ltc_mod.CRYPT_PK_INVALID_PADDING:
        return "Invalid padding mode."
    # Extra str is for Python 2 to get a native string.
    return str(func(errno).decode())


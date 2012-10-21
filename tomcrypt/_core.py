import ctypes

from . import meta


# Import the module, and get a ctypes library for it.
ltc_mod = __import__(meta.module_name, fromlist=['c'])
ltc = ctypes.CDLL(ltc_mod.__file__)

print ltc

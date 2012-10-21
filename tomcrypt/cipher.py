from .core import *
from . import meta


# These will be run by nose.
def _internal_tests():
    for name in meta.cipher_names:
        if not name.endswith('_enc'):
            yield name, LTC.function('%s_test' % name, C.int)
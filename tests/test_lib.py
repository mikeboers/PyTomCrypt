from __future__ import print_function

from . import *

from tomcrypt import core
from tomcrypt._core import ltc_mod
from tomcrypt import cipher

class TestLib(TestCase):
    
    def test_crypt_ok(self):
        self.assertEqual(ltc_mod.CRYPT_OK, 0)
    
    def test_cipher_internal(self):
        for name, test in cipher._internal_tests():
            out = test()
            if out:
                self.fail('Failed internal test for %r; %s (%d)' % (name, core.error_to_string, out))
    
    
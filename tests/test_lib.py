from __future__ import print_function

from . import *

from tomcrypt import core
from tomcrypt.core import LTC
from tomcrypt import cipher
from tomcrypt import hash

class TestLib(TestCase):
    
    def test_crypt_ok(self):
        self.assertEqual(LTC.pymod.CRYPT_OK, 0)
    
    def test_cipher_internal(self):
        for name, test in cipher._internal_tests():
            out = test()
            if out:
                self.fail('Failed internal test for %r; %s (%d)' % (name, core.error_to_string, out))
    
    def test_hash_internal(self):
        for name, test in hash._internal_tests():
            out = test()
            if out:
                self.fail('Failed internal test for %r; %s (%d)' % (name, core.error_to_string, out))
    
    
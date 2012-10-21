from __future__ import print_function

from . import *

from tomcrypt import core
from tomcrypt._core import ltc_mod


class TestLib(TestCase):
    
    def test_crypt_ok(self):
        self.assertEqual(ltc_mod.CRYPT_OK, 0)
    
from __future__ import print_function

from . import *

from tomcrypt import _core as core
from tomcrypt._core import ltc_mod


class TestLib(TestCase):
    
    def test_crypt_ok(self):
        self.assertEqual(ltc_mod.CRYPT_OK, 0)
    
    def test_error_to_string(self):
        self.assertEqual(
            core.error_to_string(ltc_mod.CRYPT_OK),
            "CRYPT_OK",
        )
        # We defined this constant, but not the message.
        self.assertEqual(
            core.error_to_string(ltc_mod.CRYPT_INVALID_PACKET),
            "Invalid input packet.",
        )

from __future__ import division

from . import *

from tomcrypt import cipher
from tomcrypt.cipher import *


def load_tests(loader, tests, ignore):
    tests.addTests(get_doctests(cipher))
    return tests


class GCMTests(TestCase):

    def test_basic_roundtrip(self):

        nonzero = b'0123456789abcdef'
        c = cipher.aes(nonzero, nonzero, 'gcm')

        c.add_aad('additional authenticated data')
        ct = c.encrypt(nonzero)
        tag1 = c.done()

        c = cipher.aes(nonzero, nonzero, 'gcm')
        c.add_aad('additional authenticated data')
        pt = c.decrypt(ct)
        tag2 = c.done()

        self.assertEqual(pt, nonzero)
        self.assertNotEqual(pt, ct)
        self.assertEqual(tag1, tag2)





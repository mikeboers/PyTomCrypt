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

    def test_aad_only_in_tag(self):

        nonzero = b'0123456789abcdef'
        c1 = cipher.aes(nonzero, nonzero, 'gcm')
        c2 = cipher.aes(nonzero, nonzero, 'gcm')

        c1.add_aad('adata1')
        c2.add_aad('adata2')

        ct1 = c1.encrypt(nonzero)
        ct2 = c2.encrypt(nonzero)
        tag1 = c1.done()
        tag2 = c2.done()

        self.assertEqual(ct1, ct2)
        self.assertNotEqual(tag1, tag2)





from __future__ import division

from . import *

import tomcrypt
from tomcrypt import prng
from tomcrypt.ecc import *


class TestECC(TestCase):
    
    def test_shared_secret(self):
        a = Key(128)
        b = Key(128)
        key_pairs = []
        for x in a, a.public:
            for y in b, b.public:
                key_pairs.append((x, y))
                key_pairs.append((y, x))

        secrets = []
        for x, y in key_pairs[:-2]:
            secrets.append(x.shared_secret(y))
        for x, y in key_pairs[-2:]:
            self.assertRaises(tomcrypt.Error, x.shared_secret, y)

        for x in secrets[1:]:
            self.assertEqual(secrets[0], x)

    def test_as_string(self):
        key = Key(128)
        self.assertTrue('BEGIN EC PRIVATE' in key.as_string())
        self.assertTrue('BEGIN PUBLIC' in key.as_string('public'))
        self.assertTrue('BEGIN PUBLIC' in key.public.as_string())
        self.assertTrue('BEGIN PUBLIC' in key.public.as_string(ansi=True))
        self.assertRaises(tomcrypt.Error, key.public.as_string, type='private')
        self.assertRaises(tomcrypt.Error, key.as_string, ansi=True)

    def test_equality(self):
        a = Key(128)
        b = Key(a.as_string())
        self.assertEqual(a.as_dict(), b.as_dict())
        c = Key(128)
        self.assertNotEqual(a.as_dict(), c.as_dict())
    
    def test_import_export(self):
        a = Key(128)
        b = Key(a.as_string())

        self.assertEqual(a.as_dict(), Key(a.as_string()).as_dict())
        self.assertEqual(a.public.as_dict(),
                Key(a.public.as_string()).as_dict())
        self.assertEqual(a.public.as_dict(),
                Key(a.as_string(type='public')).as_dict())
        self.assertEqual(a.public.as_dict(),
                Key(a.as_string(type='public', ansi=True)).as_dict())

    def test_encrypt(self):
        key = Key(128)
        msg = b"Hello, world!"
        ct1 = key.encrypt(bytearray(msg))
        ct2 = key.encrypt(msg)

        self.assertNotEqual(ct1, ct2)

        self.assertEqual(key.decrypt(ct1), msg)
        self.assertEqual(key.decrypt(bytearray(ct1)), msg)
        self.assertEqual(key.decrypt(ct2), msg)
        self.assertEqual(key.decrypt(bytearray(ct2)), msg)





from __future__ import division

import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from pprint import pprint, pformat
import time
from subprocess import Popen, PIPE
import hashlib

import tomcrypt
from tomcrypt import prng
from tomcrypt.ecc import *
from unittest import TestCase, main


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



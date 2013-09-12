from __future__ import division

import time

from six.moves import xrange

from . import *

from tomcrypt import utils
from tomcrypt.utils import *


def load_tests(loader, tests, ignore):
    tests.addTests(get_doctests(utils))
    return tests


class TestUtils(TestCase):

    def test_xor_bytes_len_mismatch(self):
        self.assertRaises(ValueError, utils.xor_bytes, b'', b'a')

    def test_xor_bytes(self):
        self.assertEqual(
            b16encode(utils.xor_bytes(
                b16decode(b'0123456789abcdef'),
                b16decode(b'0000000000000000'),
            )),
            b'0123456789abcdef',
        )

        self.assertEqual(
            b16encode(utils.xor_bytes(
                b16decode(b'0123456789abcdef'),
                b16decode(b'0123456789abcdef'),
            )),
            b'0000000000000000',
        )

    def test_bytes_equal_len_mismatch(self):
        self.assertRaises(ValueError, utils.bytes_equal, b'', b'a')

    def test_bytes_equal(self):
        self.assertTrue(utils.bytes_equal(b'', b''))
        self.assertTrue(utils.bytes_equal(b'a', b'a'))
        self.assertFalse(utils.bytes_equal(b'a', b'b'))
        self.assertFalse(utils.bytes_equal(b'hello', b'world'))
        self.assertTrue(utils.bytes_equal(b'aaaaa', b'aaaaa'))
        self.assertFalse(utils.bytes_equal(b'aaaaa', b'aaaab'))
        self.assertTrue(utils.bytes_equal(b'aaaaa', b'aaaaa'))
        self.assertTrue(utils.bytes_equal(
            b16decode(b'0123456789abcdef'),
            b16decode(b'0123456789abcdef'),
        ))
        self.assertFalse(utils.bytes_equal(
            b16decode(b'0123456789abcdef'),
            b16decode(b'0123456779abcdef'),
        ))

    def test_bytes_equal_timing(self):

        size = 2**14
        iterations = 2**10

        a = b'0' * size
        b = b'0' * size

        equal_time = time.time()
        for i in xrange(iterations):
            utils.bytes_equal(a, b)
        equal_time = time.time() - equal_time

        b = b'1' * size

        nonequal_time = time.time()
        for i in xrange(iterations):
            utils.bytes_equal(a, b)
        nonequal_time = time.time() - nonequal_time

        # I have no idea if this is a reasonable test...
        self.assertTrue(abs(equal_time - nonequal_time) - (nonequal_time / iterations))





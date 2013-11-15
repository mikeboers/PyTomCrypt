from __future__ import division

from . import *

import hmac

from tomcrypt import mac
from tomcrypt import Error as TomCryptError


def load_tests(loader, tests, ignore):
    tests.addTests(get_doctests(mac))
    return tests


class TestMAC(TestCase):

    def test_single_digest(self):
        for i in range(1, 10):
            key = os.urandom(8 * i)
            x = hmac.new(key)
            y = mac.MAC('hmac', 'md5', key)
            for j in range(1, 10):
                v = os.urandom(j * 8)
                x.update(v)
                y.update(v)
            assert x.digest() == y.digest()

    def test_mutiple_digests(self):
        i = j = -1
        try:
            for i in range(1, 10):
                j = -1
                key = os.urandom(8 * i)
                x = hmac.new(key)
                y = mac.MAC('hmac', 'md5', key)
                for j in range(1, 10):
                    v = os.urandom(j * 8)
                    x.update(v)
                    y.update(v)
                    assert x.digest() == y.digest()
        except (AssertionError, TomCryptError) as e:
            assert False, 'failed on %d-%d: %r' % (i, j, e)

    def test_copy(self):
        i = j = -1
        try:
            for i in range(1, 10):
                j = -1
                key = os.urandom(8 * i)
                x = mac.MAC('hmac', 'md5', key)
                for j in range(1, 10):
                    v = os.urandom(j * 8)
                    y = x.copy()
                    x.update(v)
                    y.update(v)
                    assert x.digest() == y.digest()
                    d = x.digest()
                    y = x.copy()
                    y.update(v)
                    assert y.digest() != d
                    assert x.digest() == d
        except (AssertionError, TomCryptError) as e:
            assert False, 'failed on %d-%d: %r' % (i, j, e)


    def test_bytes_api(self):

        assert 'hmac' in mac.names

        msg = b'hello, world'
        self.assertEqual(
            mac.hmac('sha256', b'key', msg).hexdigest(),
            '05f54fa636be6f66761a26fcb19eabf339c934798b65bce8b31027d91078264c'
        )

        self.assertEqual(
            mac.hmac('sha256', bytearray(b'key'), bytearray(msg)).hexdigest(),
            '05f54fa636be6f66761a26fcb19eabf339c934798b65bce8b31027d91078264c',
        )

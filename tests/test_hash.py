from __future__ import division, print_function

from . import *

from tomcrypt.hash import *
from tomcrypt import hash


def load_tests(loader, tests, ignore):
    tests.addTests(get_doctests(hash))
    return tests


class TestHashed(TestCase):

    def test_against_hashlib(self):
        for name in hash.names:
            if name == 'chc':
                continue
            try:
                y = hashlib.new(name)
            except ValueError:
                continue
            yield self.check_hashlib, name

    def check_hashlib(self, name):        
        x = Hash(name)
        y = hashlib.new(name)
        for i in range(100):
            s = os.urandom(i)
            x.update(s)
            y.update(s)
            assert x.digest() == y.digest()
        x2 = x.copy()
        x2.update(b'something else')
        assert x.digest() == y.digest()
        assert x2.digest() != y.digest()


    def test_bytes_api(self):
        assert 'sha256' in hash.names
        obj = hash.sha256(b'hello,')
        obj.update(b' world')
        assert obj.hexdigest() == '09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b'

    def test_bytearray_api(self):
        obj = hash.sha256(bytearray(b'hello,'))
        obj.update(bytearray(b' world'))
        assert obj.hexdigest() == '09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b'

from unittest import TestCase, main
from base64 import b16encode
import doctest

from tomcrypt import prng

from . import get_doctests


def load_tests(loader, tests, ignore):
    tests.addTests(get_doctests(prng))
    return tests


class TestPRNG(TestCase):
    
    def test_library(self):
        prng.test_library()

    def test_seeds(self):
        
        x = prng.fortuna()
        x.add_entropy(b'12345678')
        # print x.read(16).encode('hex')
        assert b16encode(x.read(16)).lower() == b'b1f2630e4b56ff6f1e0e5d6f1324a10d'
        
        x = prng.rc4()
        x.add_entropy(b'12345678')
        # print x.read(16).encode('hex')
        assert b16encode(x.read(16)).lower() == b'0a015ada42e721c8ee3d57a0b519a9a8'
        
        x = prng.sober128()
        x.add_entropy(b'12345678')
        # print x.read(16).encode('hex')
        assert b16encode(x.read(16)).lower() == b'39e10e5ccaa9a24c26abaf73dbf2e3f6'
        
        x = prng.yarrow()
        x.add_entropy(b'12345678')
        # print x.read(16).encode('hex')
        assert b16encode(x.read(16)).lower() == b'f63c36f72ad5098e42ac002243d2cce2'


if __name__ == '__main__':
    main()

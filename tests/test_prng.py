from . import *

from tomcrypt import prng
from tomcrypt import utils


def load_tests(loader, tests, ignore):
    tests.addTests(get_doctests(prng))
    return tests


class TestPRNG(TestCase):
    
    def test_library(self):
        prng.test_library()

    def test_isolation(self):
        for name in ('rc4', 'yarrow', 'fortuna', 'sober128'):
            for seed in (
                b'12345678',
                b16decode(b'0123456789ABCDEF'),
            ):
                self._test_isolation(name, seed)

    def _test_isolation(self, name, seed):
        constructor = getattr(prng, name)
        x = constructor(seed)
        y = constructor(seed)
        a = x.read(8)
        b = y.read(8)
        self.assertEqual(a, b, '%s != %s on %s with seed %s' % (
            b16encode(a),
            b16encode(b),
            name,
            b16encode(seed),
        ))

    def test_fortuna_vector(self):
        x = prng.fortuna()
        x.add_entropy(b'12345678')
        self.assertEqual(
            b16encode(x.read(8)),
            b'b1f2630e4b56ff6f'
        )
    
    def test_rc4_lib_vector(self):
        x = prng.rc4()
        seed = b16decode(b'0123456789ABCDEF')
        x.add_entropy(seed)
        
        output = x.read(8)
        output = utils.xor_bytes(output, seed)

        self.assertEqual(
            b16encode(output),
            b'75b7878099e0c596'
        )

    def test_rc4_vector(self):
        x = prng.rc4()
        x.add_entropy(b'12345678')
        self.assertEqual(
            b16encode(x.read(8)),
            b'bbf339d409b1dea7'
        )
    
    def test_sober128_vector(self):
        x = prng.sober128()
        x.add_entropy(b'12345678')
        self.assertEqual(
            b16encode(x.read(8)),
            b'33e05486884e8384'
        )
    
    def test_yarrow_vector(self):
        x = prng.yarrow()
        x.add_entropy(b'12345678')
        self.assertEqual(
            b16encode(x.read(8)).lower(),
            b'f63c36f72ad5098e'
        )

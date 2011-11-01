# vim: set syntax=pyrex

from __future__ import division

import math

from tomcrypt._core cimport *
from tomcrypt._core import Error
from tomcrypt.prng cimport PRNG, conform_prng


TYPE_PRIVATE = 'private'
TYPE_PUBLIC  = 'public'


cdef class Curve(object):

    cdef ecc_curve curve
    
    cdef readonly object name
    cdef readonly object bits
    cdef readonly object size
    cdef readonly object prime
    cdef readonly object B
    cdef readonly object order
    cdef readonly object Gx
    cdef readonly object Gy

    def __cinit__(self, prime, B, order, Gx, Gy):
        self.name  = 'curve'
        self.bits  = int(math.log(int(prime), 2))
        self.size  = int(math.ceil(self.bits / 8))
        self.prime = '%X' % int(prime)
        self.B     = '%X' % int(B)
        self.order = '%X' % int(order)
        self.Gx    = '%X' % int(Gx)
        self.Gy    = '%X' % int(Gy)
    
        self.curve.name = self.name
        self.curve.size = self.size
        self.curve.prime = self.prime
        self.curve.B = self.B
        self.curve.order = self.order
        self.curve.Gx = self.Gx
        self.curve.Gy = self.Gy


cdef class Key(object):

    cdef ecc_key key

    def __cinit__(self, input, **kwargs):
        if isinstance(input, Curve):
            self._make_key(input, kwargs.get('prng'))
        else:
            raise ValueError('cannot make key from %r' % type(input))

    cdef _make_key(self, Curve curve, raw_prng):
        cdef PRNG prng = conform_prng(raw_prng)
        check_for_error(ecc_make_key_ex(&prng.state, prng.idx, &self.key, &curve.curve))

    def as_dict(self, int radix=16):
        """Return a dict of all of the key parts encoded into strings.

        Params:
            radix -- The base into which to convert the bignum. From 2-64.

        """

        # TODO: Figure out the best size for this buffer.
        cdef char buf[1024]
        out = {}
        <% key_parts = 'public.x', 'public.y', 'public.z', 'private' %>
        % for x in key_parts:
        if self.key.${x} != NULL:
            check_for_error(mp.write_radix(self.key.${x}, buf, radix))
            out[${repr(x)}] = buf
        % endfor
        return out

    @property
    def type(self):
        """'private' or 'public'"""
        return TYPE_PRIVATE if self.is_private else TYPE_PUBLIC

    @property
    def is_private(self):
        """True if this is a private key."""
        return self.key.type == PK_PRIVATE

    @property
    def is_public(self):
        """True if this is a public key."""
        return self.key.type == PK_PUBLIC

    @property
    def size(self):
        """The bit length of the modulus of the key.

        This will be a multiple of 8 for any key generated with this library,
        but that is not a requirement for others. (It is easy to make any
        size key with openssl, for instance.)

        """
        return 1
        # return mp.count_bits(self.key.curve.prime)




P112 = Curve(
    0xDB7C2ABF62E35E668076BEAD208B,
    0x659EF8BA043916EEDE8911702B22,
    0xDB7C2ABF62E35E7628DFAC6561C5,
    0x09487239995A5EE76B55F9C2F098,
    0xA89CE5AF8724C0A23E0E0FF77500,
)

P128 = Curve(
    0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF,
    0xE87579C11079F43DD824993C2CEE5ED3,
    0xFFFFFFFE0000000075A30D1B9038A115,
    0x161FF7528B899B2D0C28607CA52C5B86,
    0xCF5AC8395BAFEB13C02DA292DDED7A83,
)

P160 = Curve(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF,
    0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45,
    0x0100000000000000000001F4C8F927AED3CA752257,
    0x4A96B5688EF573284664698968C38BB913CBFC82,
    0x23A628553168947D59DCC912042351377AC5FB32,
)

P192 = Curve(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF,
    0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1,
    0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831,
    0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012,
    0x7192B95FFC8DA78631011ED6B24CDD573F977A11E794811,
)

P224 = Curve(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001,
    0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D,
    0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21,
    0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34,
)

P256 = Curve(
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)

P384 = Curve(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
    0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
    0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
    0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
)

P521 = Curve(
    0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
    0x51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
    0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
    0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
    0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650,
)


curves = [P112, P128, P160, P192, P224, P256, P384, P521]


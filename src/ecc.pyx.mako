# vim: set syntax=pyrex

from __future__ import division

import math

from tomcrypt._core cimport *
from tomcrypt._core import Error
from tomcrypt.prng cimport PRNG, conform_prng
from tomcrypt.hash cimport Descriptor as HashDescriptor, conform_hash


TYPE_PRIVATE = 'private'
TYPE_PUBLIC  = 'public'


cdef curve_param_to_int(x):
    if isinstance(x, basestring):
        return int(x, 16)
    return int(x)


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
        
        % for attr in 'prime B order Gx Gy'.split():
        ${attr} = curve_param_to_int(${attr})
        % endfor

        self.name  = ''
        self.bits  = int(math.log(prime, 2))
        self.size  = int(math.ceil(self.bits / 8))
        
        self.curve.name = self.name
        self.curve.size = self.size
        
        % for attr in 'prime B order Gx Gy'.split():
        self.${attr} = '%X' % int(${attr})
        self.curve.${attr} = self.${attr}

        % endfor


cdef object sentinel = object()


cdef class Key(object):

    cdef readonly Curve curve
    cdef ecc_key key
    cdef Key _public

    def __cinit__(self, input, **kwargs):
        if isinstance(input, Curve):
            self.curve = input
            self._make_key(input, kwargs.get('prng'))
        elif input is not sentinel:
            raise ValueError('cannot make ECC key from %r' % input)

    def __dealloc__(self):
        ecc_free(&self.key)

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

    cdef Key public_copy(self):
        """Get a copy of this key with only the public parts."""
        cdef Key copy = self.__class__(sentinel)

        copy.curve = self.curve

        copy.key.type = PK_PUBLIC
        copy.key.idx = self.key.idx
        copy.key.curve = self.key.curve

        % for x in 'public.x', 'public.y', 'public.z':
        check_for_error(mp.init_copy(&copy.key.${x}, self.key.${x}))
        % endfor

        return copy

    @property
    def public(self):
        """A view of this key with only the public part.

        If this is already a public key, this will be the same object.

        """
        if self._public is None:
            if self.is_public:
                self._public = self
            else:
                self._public = self.public_copy()
        return self._public

    def encrypt(self, message, hash=None, prng=None):
        cdef HashDescriptor c_hash = conform_hash(hash, 'sha256')
        cdef PRNG c_prng = conform_prng(prng)
        cdef unsigned long length = 1024 + max(len(message), c_hash.desc.block_size)
        output = PyString_FromStringAndSize(NULL, length)
        check_for_error(ecc_encrypt_key(
            message, len(message),
            output, &length,
            &c_prng.state, c_prng.idx,
            c_hash.idx,
            &self.key
        ))
        return output[:length]

    def decrypt(self, message):
        cdef unsigned long length = len(message)
        output = PyString_FromStringAndSize(NULL, length)
        check_for_error(ecc_decrypt_key(
            message, length,
            output, &length,
            &self.key
        ))
        return output[:length]
        



cdef Curve _curve
% for i, size in enumerate([112, 128, 160, 192, 224, 256, 384, 521]):
_curve = Curve(
    % for attr in 'prime B order Gx Gy'.split():
    ecc_curves[${i}].${attr},
    % endfor
)
% for attr in 'name size'.split():
_curve.${attr} = ecc_curves[${i}].${attr}
% endfor
P${size} = _curve

% endfor


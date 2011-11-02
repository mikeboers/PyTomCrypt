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
    cdef readonly object size
    cdef readonly object bytes
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
        self.size  = int(math.log(prime, 2))
        self.bytes = int(math.ceil(self.size / 8))
        
        self.curve.name = self.name
        self.curve.size = self.bytes
        
        % for attr in 'prime B order Gx Gy'.split():
        self.${attr} = '%X' % int(${attr})
        self.curve.${attr} = self.${attr}

        % endfor


# This object will be used as a sentinel to stop user code from instantiating
# blank Key objects.
cdef object key_init_sentinel = object()


cdef class Key(object):

    cdef readonly Curve curve
    cdef ecc_key key
    cdef Key _public

    def __cinit__(self, input, prng=None):

        # If given an int, pick a curve that is atleast that many bits.
        if isinstance(input, int):
            for size, curve in curves_by_size:
                if size >= input:
                    break
            else:
                raise Error('no NIST curve at least %d bits' % input)
            input = curve

        # If given a curve, make a random key for that curve.
        if isinstance(input, Curve):
            self._make_key(input, prng)
            self.curve = input
        
        # Don't let user code instantiate blank keys.
        elif input is not key_init_sentinel:
            raise Error('cannot make ECC key from %r' % input)

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

    def as_string(self, format='der', ansi=False):
        cdef unsigned long length = 1024
        output = PyString_FromStringAndSize(NULL, length)
        
        if ansi:
            check_for_error(ecc_ansi_x963_export(&self.key, output, &length))
        else:
            check_for_error(ecc_export(output, &length, self.key.type, &self.key))
        
        return output[:length]

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

    cdef Key _public_copy(self):
        """Get a copy of this key with only the public parts."""
        cdef Key copy = self.__class__(key_init_sentinel)

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
                self._public = self._public_copy()
        return self._public

    def shared_secret(self, Key other):
        cdef Key private = self
        cdef Key public = other

        if not private.is_private:
            private, public = public, private
        if not private.is_private:
            raise Error('one of the keys must be private')

        cdef unsigned long length = 1024
        output = PyString_FromStringAndSize(NULL, length)
        check_for_error(ecc_shared_secret(
            &private.key,
            &public.key,
            output,
            &length
        ))
        return output[:length]

    def encrypt(self, message, hash=None, prng=None):
        cdef HashDescriptor c_hash = conform_hash(hash or 'sha256')
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

    def sign(self, message, prng=None):
        cdef PRNG c_prng = conform_prng(prng)
        cdef unsigned long length = 1024 + self.curve.size
        output = PyString_FromStringAndSize(NULL, length)
        check_for_error(ecc_sign_hash(
            message, len(message),
            output, &length,
            &c_prng.state, c_prng.idx,
            &self.key
        ))
        return output[:length]

    def verify(self, message, sig):
        cdef int stat
        check_for_error(ecc_verify_hash(
            sig, len(sig),
            message, len(message),
            &stat,
            &self.key
        ))
        return bool(stat)



        


cdef list curves_by_size = []

cdef Curve _curve
% for i, size in enumerate([112, 128, 160, 192, 224, 256, 384, 521]):
_curve = Curve(
    % for attr in 'prime B order Gx Gy'.split():
    ecc_nist_curves[${i}].${attr},
    % endfor
)
% for cattr, attr in dict(name='name', size='bytes').iteritems():
_curve.${attr} = ecc_nist_curves[${i}].${cattr}
_curve.curve.${cattr} = _curve.${attr}
% endfor
P${size} = _curve
curves_by_size.append((${size}, P${size}))

% endfor


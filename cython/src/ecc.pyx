# vim: set syntax=pyrex

from __future__ import division

import math

from tomcrypt._core cimport *
from tomcrypt._core import Error
from tomcrypt.prng cimport PRNG, conform_prng
from tomcrypt.hash cimport Descriptor as HashDescriptor, conform_hash
from tomcrypt.utils import pem_encode, pem_decode

TYPE_PRIVATE = 'private'
TYPE_PUBLIC  = 'public'


curve_sizes = [112, 128, 160, 192, 224, 256, 384, 521]


# Stub.
cdef class Key


cdef class Curve(object):
    """A elliptic curve for use in ECC.
    
    Due to LibTomCrypt's limitations and implementation, we will only use the 8
    recommended curves as provided by LibTomCrypt.

    Passing a bit size to the constructor will yield the smallest curve of at
    least the given size.
    
    """

    cdef readonly int idx
    cdef readonly int bits
    cdef ecc_curve *curve
    
    def __cinit__(self, size):
        
        cdef int idx, nist_size
        for idx, nist_size in enumerate(curve_sizes):
            if size <= nist_size:
                break
        else:
            raise Error('no curve of at least %d bits' % size)

        self.idx = idx
        self.bits = nist_size
        self.curve = &ecc_nist_curves[idx]
        
    % for name in 'name size'.split():
    @property
    def ${name}(self):
        return self.curve.${name}
    % endfor

    cpdef Key make_key(self):
        return Key(self)




# This object will be used as a sentinel to stop user code from instantiating
# blank Key objects.
cdef object key_init_sentinel = object()


cdef class Key(object):
    """An ECC key.

    Attributes:
        curve -- The Curve object used with this key.
        public -- The public component of this key.

    Constructor Params:
        curve -- int of the minimum bit size of key to use (picks from the
            NIST recommended curves), or a Curve to use directly.
        prng -- The PRNG to use to generate the key; defaults to "sprng".

    """

    cdef readonly Curve curve
    cdef ecc_key key
    cdef Key _public

    def __cinit__(self, curve, prng=None):

        # If given a string, try to import it.
        if isinstance(curve, (unicode, str)):
            self._from_string(curve)
            return

        # If given an int, pick a curve that is atleast that many bits.
        if isinstance(curve, (int, long)):
            curve = Curve(curve)

        # If given a curve, make a random key for that curve.
        if isinstance(curve, Curve):
            self._make_key(curve, prng)
            self.curve = curve
            return
        
        # Don't let user code instantiate blank keys.
        elif curve is not key_init_sentinel:
            raise Error('cannot make ECC key from %r' % curve)

    def __dealloc__(self):
        # Need to explicitly test if it needs dealocating.
        if self.key.public.x != NULL:
            ecc_free(&self.key)

    cdef _make_key(self, Curve curve, raw_prng):
        cdef PRNG prng = conform_prng(raw_prng)
        check_for_error(ecc_make_key_ex(&prng.state, prng.idx, &self.key, curve.curve))
        self.key.idx = curve.idx

    cdef _from_string(self, input):
        
        self._public = None

        try:
            type, mode, input = pem_decode(input)
        except Error:
            pass
        try:
            check_for_error(ecc_import(input, len(input), &self.key))
        except:
            # Mark that this doesn't need deallocating.
            self.key.public.x = NULL
            raise
        
        if self.key.idx < 1:
            raise Error('unknown curve in imported key')
        self.curve = Curve(ecc_nist_curves[self.key.idx].size)


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
            val = buf
            if val != b'0':
                out[${repr(x)}] = val
            
        % endfor
        return out

    def as_string(self, type=None, format='pem', ansi=False):
        """Build the string representation of a key.

        Params:
            type -- None (as is), 'private' or 'public'.
            format -- 'pem' (default), or 'der'.

        """

        cdef unsigned long length = 1024
        output = PyBytes_FromStringAndSize(NULL, length)
        
        if type is None:
            type = self.type
        if type not in ('public', 'private'):
            raise Error('unknown type %r' % type)
        if type == 'private' and self.type == 'public':
            raise Error('cannot export private key from public key')
        if type == 'private' and ansi:
            raise Error('cannot export private key in ANSI format')
        
        if ansi:
            check_for_error(ecc_ansi_x963_export(&self.key, output, &length))
        else:
            check_for_error(ecc_export(output, &length, PK_PRIVATE if type ==
                'private' else PK_PUBLIC, &self.key))

        if format == 'der':
            return output[:length]
        return pem_encode('EC', type.upper(), output[:length])
        
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
        output = PyBytes_FromStringAndSize(NULL, length)
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
        output = PyBytes_FromStringAndSize(NULL, length)
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
        output = PyBytes_FromStringAndSize(NULL, length)
        check_for_error(ecc_decrypt_key(
            message, length,
            output, &length,
            &self.key
        ))
        return output[:length]

    def sign(self, message, prng=None):
        cdef PRNG c_prng = conform_prng(prng)
        cdef unsigned long length = 1024 + self.curve.size
        output = PyBytes_FromStringAndSize(NULL, length)
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
    



        



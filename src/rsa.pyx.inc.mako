<%!

key_parts = 'e d N p q qP dP dQ'.split()

%>

import re
import base64
from math import ceil


RSA_TYPE_PRIVATE = 'private'
RSA_TYPE_PUBLIC  = 'public'

cdef object _rsa_type_map = {
    RSA_TYPE_PRIVATE: c_RSA_TYPE_PRIVATE,
    RSA_TYPE_PUBLIC : c_RSA_TYPE_PUBLIC,
}


cdef c_RSA_PAD_NONE = 0
RSA_PAD_NONE = 'none'
RSA_PAD_V1_5 = 'v1.5'
RSA_PAD_OAEP = 'oaep'
RSA_PAD_PSS  = 'pss'

cdef object _rsa_pad_map = {
    RSA_PAD_NONE: c_RSA_PAD_NONE,
    RSA_PAD_V1_5: c_RSA_PAD_V1_5,
    RSA_PAD_OAEP: c_RSA_PAD_OAEP,
    RSA_PAD_PSS : c_RSA_PAD_PSS,
}


RSA_FORMAT_PEM = 'pem'
RSA_FORMAT_DER = 'der'


RSA_DEFAULT_ENC_HASH = 'sha1'
RSA_DEFAULT_SIG_HASH = 'sha512'
RSA_DEFAULT_PRNG = 'sprng'

RSA_DEFAULT_SIZE = 1024 / 8
RSA_DEFAULT_E = 65537



cdef int rsa_conform_padding(padding):
    """Turn a user supplied padding constant into the C variant."""
    if padding not in _rsa_pad_map:
        raise ValueError('unknown RSA padding %r' % padding)
    padding = _rsa_pad_map[padding]
    return padding


cdef PRNG rsa_conform_prng(prng):
    """Turn a user supplied PRNG into an actual PRNG.

    If only a name or idx is supplied, it is autoseeded from the system rng.
    None defaults to the system rng (ie /dev/random).

    """
    if isinstance(prng, PRNG):
        return prng
    if prng is None:
        return PRNG(RSA_DEFAULT_PRNG)
    return PRNG(prng, auto_seed=1024)


cdef HashDescriptor rsa_conform_hash(hash, default):
    """Turn a user supplied hash into a HashDescriptor."""
    if isinstance(hash, HashDescriptor):
        return hash
    if hash is None:
        return HashDescriptor(default)
    return HashDescriptor(hash)


cdef unsigned long rsa_conform_saltlen(self, saltlen, HashDescriptor hash):
    """Turn a user supplied saltlen into an appropriate object.

    Defaults to as long a salt as possible if not supplied.

    """
    if saltlen is None:
        return self.size - hash.digest_size - 2
    return saltlen


def rsa_max_payload(int key_size, padding=RSA_PAD_OAEP, hash=None):
    """Find the maximum length of the payload that is safe to encrypt/sign.

    Params:
        padding -- The padding that will be used.
        hash -- The hash that will be used.

    """
    padding = rsa_conform_padding(padding)
    hash = rsa_conform_hash(hash, RSA_DEFAULT_ENC_HASH)
    if padding == c_RSA_PAD_NONE:
        return key_size
    elif padding == c_RSA_PAD_OAEP:
        return key_size - 2 * hash.digest_size - 2
    elif padding == c_RSA_PAD_PSS:
        return key_size - hash.digest_size - 2
    else:
        # RSA_PAD_V1_5 - I'm not too sure about this one.
        return key_size - 2


def rsa_key_size_for_payload(int length, padding=RSA_PAD_OAEP, hash=None):
    """Determine the min keysize for a payload of a given length.

    This is for OAEP padding with the given (or default) hash.

    """
    padding = rsa_conform_padding(padding)
    hash = rsa_conform_hash(hash, RSA_DEFAULT_ENC_HASH)
    if padding == c_RSA_PAD_NONE:
        return length
    elif padding == c_RSA_PAD_OAEP:
        return length + 2 * hash.digest_size + 2
    elif padding == c_RSA_PAD_PSS:
        return length + hash.digest_size + 2
    else:
        # RSA_PAD_V1_5 - I'm not too sure about this one.
        return length + 2


# This object must be passed to the RSAKey constructor in order for an
# instance to be created. This is to assert that keys can only be created by
# the C code. This is a BAD idea.
cdef object _rsa_key_init_sentinel = object()

cdef class RSAKey

cdef RSAKey rsa_new_key(cls):
    """Create a new uninitialized key object.

    This must be used as we do not allow one to create a key with the normal
    constructor (to make sure we don't have any keys in an undefined state).

    """
    return cls(_rsa_key_init_sentinel)


# Regular expression for determining and extracting PEM data.
cdef object _rsa_pem_re = re.compile(r'^\s*-----BEGIN ((?:RSA )?(?:PRIVATE|PUBLIC)) KEY-----(.+)-----END \1 KEY-----', re.DOTALL)


cdef class RSAKey(object):

    cdef rsa_key key
    cdef RSAKey _public

    # The sentinel checking code is in the cinit because I believe it is the
    # only place that it cannot be overidden.
    def __cinit__(self, input=None, **kwargs):

        cdef unsigned long size, e
        cdef PRNG prng

        if isinstance(input, basestring):
            format = kwargs.pop('format', None)
            if kwargs:
                raise ValueError('too many kwargs')
            self._from_string(input, format)

        elif 'size' in kwargs or isinstance(input, int):
            size = kwargs.pop('size', input)
            e = kwargs.pop('e', RSA_DEFAULT_E)
            prng = kwargs.pop('prng', None)
            self._generate(size, e, prng)

        elif input is None:
            raise ValueError('must supply input')

        elif input is not _rsa_key_init_sentinel:
            raise ValueError('unknown key input')

    def __dealloc__(self):
        # It has been my experience that I must manually check to make sure
        # that the key has been setup before I try to use it. Therefore, I
        # am checking if the modulus has been inited. I'm going to assume if
        # the modulus was inited, then the rest of the key will be inited as
        # well.
        #
        # BUT, if we tried to make a key or import one and it FAILED, this
        # will still attempt to free the key. Caution must be taken to make
        # sure that a failed key is NEVER stored in this class. Ergo, the
        # nullify method.
        if self.key.N != NULL:
            rsa_free(&self.key)

    cdef nullify(self):
        """Mark the key as not needing to be freed.

        Use this after an error has occurred and the key automatically freed,
        but the pointers have not been reset to null.

        """
        self.key.N = NULL

    cdef _generate(self, int size, long e, PRNG prng):
        """The guts of the generate class method.

        This modifies the key in place. Be careful.

        """
        self._public = None
        if prng is None:
            prng = PRNG('sprng')
        try:
            check_for_error(rsa_make_key(&prng.state, prng.idx, size, e, &self.key))
        except:
            self.nullify()
            raise

    def as_string(self, type=None, format=RSA_FORMAT_PEM):
        """Build the string representation of a key.

        Both the availible formats are compatible with OpenSSL. We default to
        the same one that OpenSSL does (PEM).

        Params:
            type -- None (as is), 'private' or 'public'.
            format -- 'pem' (default), or 'der'.

        """

        if type is None:
            type = self.key.type
        elif type in _rsa_type_map:
            type = _rsa_type_map[type]
        else:
            raise ValueError('unknown key type %r' % type)

        if self.key.type == c_RSA_TYPE_PUBLIC and type == c_RSA_TYPE_PRIVATE:
            raise ValueError('cant get private key from public key')

        if format not in (RSA_FORMAT_DER, RSA_FORMAT_PEM):
            raise ValueError('unknown RSA key format %r' % format)

        # TODO: determine what size this really needs to be.
        out = PyString_FromStringAndSize(NULL, 4096)
        cdef unsigned long length = 4096
        check_for_error(rsa_export(out, &length, type, &self.key))

        if format == RSA_FORMAT_DER:
            return out[:length]
        return '-----BEGIN %(type)s KEY-----\n%(key)s-----END %(type)s KEY-----\n' % {
            'key': out[:length].encode('base64'),
            'type': 'RSA PRIVATE' if type == RSA_TYPE_PRIVATE else 'PUBLIC'
        }

    cdef _from_string(self, str input, format):
        """The guts of the from_string method.

        This modifies the key in place. Be careful.

        """
        self._public = None
        if format not in (None, RSA_FORMAT_DER, RSA_FORMAT_PEM):
            raise ValueError('unknown RSA key format %r' % format)
        if format != RSA_FORMAT_DER:
            m = _rsa_pem_re.match(input)
            if m:
                input = m.group(2).decode('base64')
            elif format == RSA_FORMAT_PEM:
                raise ValueError('bad PEM format')
        try:
            check_for_error(rsa_import(input, len(input), &self.key))
        except:
            self.nullify()
            raise

    def as_dict(self, int radix=16):
        """Return a dict of all of the key parts encoded into strings.

        Params:
            radix -- The base into which to convert the bignum. From 2-64.

        """

        # TODO: Figure out the best size for this buffer.
        cdef char buf[1024]
        out = {}
        % for x in key_parts:
        check_for_error(mp.write_radix(self.key.${x}, buf, radix))
        out[${repr(x)}] = buf
        % endfor
        return out

    @property
    def type(self):
        """'private' or 'public'"""
        return RSA_TYPE_PRIVATE if self.is_private else RSA_TYPE_PUBLIC

    @property
    def is_private(self):
        """True if this is a private key."""
        return self.key.type == c_RSA_TYPE_PRIVATE

    @property
    def is_public(self):
        """True if this is a public key."""
        return self.key.type == c_RSA_TYPE_PUBLIC

    @property
    def bitlen(self):
        """The bit length of the modulus of the key.

        This will be a multiple of 8 for any key generated with this library,
        but that is not a requirement for others. (It is easy to make any
        size key with openssl, for instance.)

        """
        return mp.count_bits(self.key.N)

    @property
    def size(self):
        """The number of characters in the modulus of the key.

        This is the minumum number of characters required to represent the
        modulus in binary form. If the bit length of the modulus is not evenly
        divisible by 8 then this will round up.

        """
        cdef int bits = mp.count_bits(self.key.N)
        return (bits / 8) + (1 if bits % 8 else 0)

    def max_payload(self, padding=RSA_PAD_OAEP, hash=None):
        """The maximum length of the payload that is safe to encrypt/sign.

        Params:
            padding -- The padding that will be used.
            hash -- The hash that will be used.

        """
        return rsa_max_payload(self.bitlen / 8, padding, hash)

    cdef RSAKey public_copy(self):
        """Get a copy of this key with only the public parts."""
        cdef RSAKey copy = rsa_new_key(self.__class__)
        copy.key.type = c_RSA_TYPE_PUBLIC
        try:
            % for x in 'Ne':
            check_for_error(mp.init_copy(&copy.key.${x}, self.key.${x}))
            % endfor
            # Just need to init these parts, which zeros them automatically.
            % for x in set(key_parts) - set('Ne'):
            check_for_error(mp.init(&copy.key.${x}))
            % endfor
        except:
            copy.nullify()
            raise
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

    cdef str raw_crypt(self, int mode, str input):
        out = PyString_FromStringAndSize(NULL, 4096)
        cdef unsigned long out_length = 4096
        check_for_error(rsa_exptmod(
            input, len(input),
            out, &out_length,
            mode,
            &self.key))
        return out[:out_length]

    cpdef encrypt(self, str input, prng=None, hash=None, padding=RSA_PAD_OAEP):

        padding = rsa_conform_padding(padding)
        if padding == c_RSA_PAD_NONE:
            return self.raw_crypt(RSA_TYPE_PUBLIC, input)

        cdef PRNG c_prng = rsa_conform_prng(prng)
        cdef HashDescriptor c_hash = rsa_conform_hash(hash, RSA_DEFAULT_ENC_HASH)

        out = PyString_FromStringAndSize(NULL, 512)
        cdef unsigned long out_length = 512
        check_for_error(rsa_encrypt_key_ex(
            input, len(input),
            out, &out_length,
            NULL, 0,
            &c_prng.state, c_prng.idx,
            c_hash.idx,
            padding,
            &self.key
        ))
        return out[:out_length]

    cpdef decrypt(self, str input, hash=None, padding=RSA_PAD_OAEP):

        padding = rsa_conform_padding(padding)
        if padding == c_RSA_PAD_NONE:
            return self.raw_crypt(RSA_TYPE_PRIVATE, input)

        cdef HashDescriptor c_hash = rsa_conform_hash(hash, RSA_DEFAULT_ENC_HASH)

        out = PyString_FromStringAndSize(NULL, 512)
        cdef unsigned long out_length = 512
        cdef int status = 0
        check_for_error(rsa_decrypt_key_ex(
            input, len(input),
            out, &out_length,
            NULL, 0,
            c_hash.idx,
            padding,
            &status,
            &self.key
        ))
        if not status:
            raise Error('Invalid padding.')
        return out[:out_length]

    cpdef sign(self, str input, prng=None, hash=None, padding=RSA_PAD_PSS, saltlen=None):

        padding = rsa_conform_padding(padding)
        if padding == c_RSA_PAD_NONE:
            return self.raw_crypt(RSA_TYPE_PRIVATE, input)

        cdef PRNG c_prng = rsa_conform_prng(prng)
        cdef HashDescriptor c_hash = rsa_conform_hash(hash, RSA_DEFAULT_SIG_HASH)
        cdef unsigned long c_saltlen = rsa_conform_saltlen(self, saltlen, c_hash)

        out = PyString_FromStringAndSize(NULL, 512)
        cdef unsigned long out_length = 512
        check_for_error(rsa_sign_hash_ex(
            input, len(input),
            out, &out_length,
            padding,
            &c_prng.state, c_prng.idx,
            c_hash.idx,
            c_saltlen,
            &self.key
        ))
        return out[:out_length]

    cpdef verify(self, str input, str sig, hash=None, padding=RSA_PAD_PSS, saltlen=None):
        """This will throw an exception if the signature could not possibly be valid."""

        padding = rsa_conform_padding(padding)
        if padding == c_RSA_PAD_NONE:
            return self.raw_crypt(RSA_TYPE_PUBLIC, input)

        cdef HashDescriptor c_hash = rsa_conform_hash(hash, RSA_DEFAULT_SIG_HASH)
        cdef unsigned long c_saltlen = rsa_conform_saltlen(self, saltlen, c_hash)

        out = PyString_FromStringAndSize(NULL, 512)
        cdef unsigned long out_length = 512
        cdef int status = 0
        check_for_error(rsa_verify_hash_ex(
            sig, len(sig),
            input, len(input),
            padding,
            c_hash.idx,
            c_saltlen,
            &status,
            &self.key
        ))
        return bool(status)

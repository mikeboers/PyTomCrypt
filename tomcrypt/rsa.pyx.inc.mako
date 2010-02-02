<%!

key_parts = 'e d N p q qP dP dQ'.split()

%>

import re
import base64
from math import ceil

RSA_TYPE_PRIVATE = _RSA_TYPE_PRIVATE
RSA_TYPE_PUBLIC  = _RSA_TYPE_PUBLIC

cdef object _rsa_type_map = {
    RSA_TYPE_PRIVATE: RSA_TYPE_PRIVATE,
    RSA_TYPE_PUBLIC : RSA_TYPE_PUBLIC,
    'private': RSA_TYPE_PRIVATE,
    'public' : RSA_TYPE_PUBLIC
}


RSA_PAD_NONE = 0
RSA_PAD_V1_5 = _RSA_PAD_V1_5 # 1
RSA_PAD_OAEP = _RSA_PAD_OAEP # 2
RSA_PAD_PSS  = _RSA_PAD_PSS  # 3

cdef object _rsa_pad_map = {
    RSA_PAD_NONE: RSA_PAD_NONE,
    RSA_PAD_V1_5: RSA_PAD_V1_5,
    RSA_PAD_OAEP: RSA_PAD_OAEP,
    RSA_PAD_PSS : RSA_PAD_PSS,
    'none': RSA_PAD_NONE,
    'v1.5': RSA_PAD_V1_5,
    'oaep': RSA_PAD_OAEP,
    'pss' : RSA_PAD_PSS,
}


RSA_FORMAT_PEM = 'pem'
RSA_FORMAT_DER = 'der'

RSA_DEFAULT_ENC_HASH = 'sha1'
RSA_DEFAULT_SIG_HASH = 'sha512'
RSA_DEFAULT_PRNG = 'sprng'






cdef int rsa_conform_padding(padding):
    if padding not in _rsa_pad_map:
        raise ValueError('unknown rsa padding %r' % padding)
    padding = _rsa_pad_map[padding]
    return padding


cdef PRNG rsa_conform_prng(prng):
    if isinstance(prng, PRNG):
        return prng
    if prng is None:
        return PRNG(RSA_DEFAULT_PRNG)
    return PRNG(prng, auto_seed=1024)


cdef HashDescriptor rsa_conform_hash(hash, default):
    if isinstance(hash, HashDescriptor):
        return hash
    if hash is None:
        return HashDescriptor(default)
    return HashDescriptor(hash)


cdef unsigned long rsa_conform_saltlen(self, saltlen, HashDescriptor hash):
    if saltlen is None:
        return (self.bits / 8) - hash.digest_size - 2
    return saltlen


# This object is just for usage as a sentinel. It must be passed to the RSAKey
# constructor.
cdef object _rsa_key_init_sentinel = object()

cdef class RSAKey

cdef RSAKey rsa_new_key(cls):
    """Create a new key object.

    This must be used as we do not allow one to init a key manually.

    """

    return cls(_rsa_key_init_sentinel)

cdef object _rsa_pem_re = re.compile(r'^\s*-----BEGIN ((?:RSA )?(?:PRIVATE|PUBLIC)) KEY-----(.+)-----END \1 KEY-----', re.DOTALL)


cdef class RSAKey(object):

    cdef rsa_key key
    cdef object _public

    def __cinit__(self, x=None):
        if x is not _rsa_key_init_sentinel:
            raise ValueError('cannot manually init new %s' % self.__class__)

    def __dealloc__(self):
        # It has been my experience that I must manually check to make sure
        # that the key has been setup before I try to use it. Therefore, I
        # am checking if the modulus has been inited. I'm going to assume if
        # the modulus was inited, then the rest of the key will be inited as
        # well.
        #
        # BUT, if we tried to make a key or import one and it FAILED, this
        # will still attempt to free the key. Caution must be taken to make
        # sure that a failed key is NEVER stored in this class.
        if self.key.N != NULL:
            rsa_free(&self.key)

    cdef nullify(self):
        self.key.N = NULL

    cdef _generate(self, int size, long e, PRNG prng):
        self._public = None
        if prng is None:
            prng = PRNG('sprng')
        try:
            check_for_error(rsa_make_key(&prng.state, prng.idx, size / 8, e, &self.key))
        except:
            self.nullify()
            raise

    @classmethod
    def generate(cls, int size=1024, long e=65537, PRNG prng=None):
        cdef RSAKey key = rsa_new_key(cls)
        key._generate(size, e, prng)
        return key

    def as_string(self, type=None, format=RSA_FORMAT_PEM):

        if type is None:
            type = self.key.type
        if type not in _rsa_type_map:
            raise ValueError('unknown key type %r' % type)
        type = _rsa_type_map[type]
        if self.key.type == _RSA_TYPE_PUBLIC and type == RSA_TYPE_PRIVATE:
            raise ValueError('cant get private key from public key')

        if format not in (RSA_FORMAT_DER, RSA_FORMAT_PEM):
            raise ValueError('unknown RSA key format %r' % format)

        out = PyString_FromStringAndSize(NULL, 4096)
        cdef unsigned long length = 4096
        check_for_error(rsa_export(out, &length, _rsa_type_map[type], &self.key))

        if format == RSA_FORMAT_DER:
            return out[:length]
        return '-----BEGIN %(type)s KEY-----\n%(key)s-----END %(type)s KEY-----\n' % {
            'key': out[:length].encode('base64'),
            'type': 'RSA PRIVATE' if type == RSA_TYPE_PRIVATE else 'PUBLIC'
        }

    cdef _from_string(self, str input):
        self._public = None
        m = _rsa_pem_re.match(input)
        if m:
            input = m.group(2).decode('base64')
        try:
            check_for_error(rsa_import(input, len(input), &self.key))
        except:
            self.nullify()
            raise

    @classmethod
    def from_string(cls, str input):
        cdef RSAKey key = rsa_new_key(cls)
        key._from_string(input)
        return key

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
        return self.key.type

    @property
    def is_private(self):
        return self.key.type == _RSA_TYPE_PRIVATE

    @property
    def is_public(self):
        return self.key.type == _RSA_TYPE_PUBLIC

    @property
    def bits(self):
        return mp.count_bits(self.key.N)

    @classmethod
    def max_payload_for_bits(cls, bits, hash=None):
        hash = rsa_conform_hash(hash, RSA_DEFAULT_ENC_HASH)
        return (bits / 8) - 2 * hash.digest_size - 2

    def max_payload(self, hash=None):
        return self.max_payload_for_bits(self.bits, hash)

    @classmethod
    def bits_for_payload(cls, size, hash=None):
        hash = rsa_conform_hash(hash, RSA_DEFAULT_ENC_HASH)
        return 8 * (size + 2 + 2 * hash.digest_size)



    cdef RSAKey copy(self):
        cdef RSAKey copy = rsa_new_key(self.__class__)
        copy.key.type = self.key.type

        % for x in key_parts:
        check_for_error(mp.init_copy(&copy.key.${x}, self.key.${x}))
        % endfor

        return copy

    cdef RSAKey copy_public(self):
        cdef RSAKey copy = rsa_new_key(self.__class__)
        copy.key.type = _RSA_TYPE_PUBLIC

        % for x in 'Ne':
        check_for_error(mp.init_copy(&copy.key.${x}, self.key.${x}))
        % endfor

        # Just need to initialize these parts, which sets them to zero.
        % for x in set(key_parts) - set('Ne'):
        check_for_error(mp.init(&copy.key.${x}))
        % endfor

        return copy

    @property
    def public(self):
        """Return a key with only the public part.

        If this is already a public key, this will be the same object.

        """

        if self._public is None:
            if self.is_public:
                self._public = self
            else:
                self._public = self.copy_public()
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
        if padding == RSA_PAD_NONE:
            return self.raw_crypt(RSA_TYPE_PUBLIC, input)

        cdef PRNG c_prng = rsa_conform_prng(prng)
        cdef HashDescriptor c_hash = rsa_conform_hash(hash, RSA_DEFAULT_ENC_HASH)

        out = PyString_FromStringAndSize(NULL, 4096)
        cdef unsigned long out_length = 4096
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
        if padding == RSA_PAD_NONE:
            return self.raw_crypt(RSA_TYPE_PRIVATE, input)

        cdef HashDescriptor c_hash = rsa_conform_hash(hash, RSA_DEFAULT_ENC_HASH)

        out = PyString_FromStringAndSize(NULL, 4096)
        cdef unsigned long out_length = 4096
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
            raise Error('invalid padding')
        return out[:out_length]

    cpdef sign(self, str input, prng=None, hash=None, padding=RSA_PAD_PSS, saltlen=None):

        padding = rsa_conform_padding(padding)
        if padding == RSA_PAD_NONE:
            return self.raw_crypt(RSA_TYPE_PRIVATE, input)
        
        cdef PRNG c_prng = rsa_conform_prng(prng)
        cdef HashDescriptor c_hash = rsa_conform_hash(hash, RSA_DEFAULT_SIG_HASH)
        cdef unsigned long c_saltlen = rsa_conform_saltlen(self, saltlen, c_hash)

        out = PyString_FromStringAndSize(NULL, 4096)
        cdef unsigned long out_length = 4096
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
        if padding == RSA_PAD_NONE:
            return self.raw_crypt(RSA_TYPE_PUBLIC, input)

        cdef HashDescriptor c_hash = rsa_conform_hash(hash, RSA_DEFAULT_SIG_HASH)
        cdef unsigned long c_saltlen = rsa_conform_saltlen(self, saltlen, c_hash)

        out = PyString_FromStringAndSize(NULL, 4096)
        cdef unsigned long out_length = 4096
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


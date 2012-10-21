# vim: set syntax=pyrex
<%!

key_parts = 'e d N p q qP dP dQ'.split()

%>

from tomcrypt._core cimport *
from tomcrypt import Error
from tomcrypt.prng cimport conform_prng
from tomcrypt.hash cimport conform_hash, Descriptor as HashDescriptor
from tomcrypt.prng cimport PRNG
from tomcrypt.utils import pem_encode, pem_decode

import re
import base64
from math import ceil


TYPE_PRIVATE = 'private'
TYPE_PUBLIC  = 'public'

cdef object type_map = {
    TYPE_PRIVATE: c_RSA_TYPE_PRIVATE,
    TYPE_PUBLIC : c_RSA_TYPE_PUBLIC,
}

cdef c_RSA_PAD_NONE = 0
PAD_NONE = 'none'
PAD_V1_5 = 'v1.5'
PAD_OAEP = 'oaep'
PAD_PSS  = 'pss'

cdef object padding_map = {
    PAD_NONE: c_RSA_PAD_NONE,
    PAD_V1_5: c_RSA_PAD_V1_5,
    PAD_OAEP: c_RSA_PAD_OAEP,
    PAD_PSS : c_RSA_PAD_PSS,
}

FORMAT_PEM = 'pem'
FORMAT_DER = 'der'

DEFAULT_ENC_HASH = 'sha1'
DEFAULT_SIG_HASH = 'sha512'

DEFAULT_SIZE = 2048
DEFAULT_E = 65537



cdef int conform_padding(padding) except -1:
    """Turn a user supplied padding constant into the C variant."""
    if isinstance(padding, str):
        padding = padding.lower()
    if padding not in padding_map:
        raise Error('unknown RSA padding %r' % padding)
    return padding_map[padding]


cdef unsigned long conform_saltlen(key, saltlen, HashDescriptor hash, padding) except? 0:
    """Turn a user supplied saltlen into an appropriate object.

    Defaults to as long a salt as possible if not supplied.

    """
    if saltlen is None:
        return max_payload(key.size, padding, hash)
    return saltlen


def max_payload(int key_size, padding=PAD_OAEP, hash=None):
    """Find the maximum length of the payload that is safe to encrypt/sign.

    Params:
        padding -- One of 'none', 'v1.5', 'oaep', or 'pss'. Defaults to 'oaep'.
        hash -- The hash that will be used. Defaults to 'sha1'.

    >>> max_payload(1024)
    86
    >>> max_payload(2048, hash='sha512')
    126
    >>> max_payload(1024, padding='none')
    128

    """
    padding = conform_padding(padding)
    hash = conform_hash(hash or DEFAULT_ENC_HASH)
    if padding == c_RSA_PAD_NONE:
        return key_size / 8
    elif padding == c_RSA_PAD_OAEP:
        return key_size / 8 - 2 * hash.digest_size - 2
    elif padding == c_RSA_PAD_PSS:
        return key_size / 8 - hash.digest_size - 2
    else:
        # PAD_V1_5 - I'm not too sure about this one.
        return key_size / 8 - 2


def key_size_for_payload(int length, padding=PAD_OAEP, hash=None):
    """Determine the min keysize for a payload of a given length.
    
    Params:
        length -- The length of the payload.
        padding -- One of 'none', 'v1.5', 'oaep', or 'pss'. Defaults to 'oaep'.
        hash -- The hash that will be used. Defaults to 'sha1'.
        
    key_size_for_payload(86)
    1024
    
    key_size_for_payload(128, padding='none')
    1024

    """
    padding = conform_padding(padding)
    hash = conform_hash(hash or DEFAULT_ENC_HASH)
    if padding == c_RSA_PAD_NONE:
        return 8 * length
    elif padding == c_RSA_PAD_OAEP:
        return 8 * (length + 2 * hash.digest_size + 2)
    elif padding == c_RSA_PAD_PSS:
        return 8 * (length + hash.digest_size + 2)
    else:
        # PAD_V1_5 - I'm not too sure about this one.
        return 8 * (length + 2)


# This object must be passed to the Key constructor in order for an
# instance to be created. This is to assert that keys can only be created by
# the C code. This is a BAD idea.
cdef object blank_key_sentinel = object()

cdef class Key

cdef Key blank_key(cls):
    """Create a new uninitialized key object.

    This must be used as we do not allow one to create a key with the normal
    constructor (to make sure we don't have any keys in an undefined state).

    """
    return cls(blank_key_sentinel)



cdef class Key(object):
    """An RSA key.

    This key can be imported from an encoded string, or randomly generated.

    >>> # Generate a key.
    >>> key = Key(1024)
    >>> key.size
    1024

    >>> # Import a key.
    >>> key = Key(open('/path/to/key.pem').read()) #doctest: +SKIP

    """

    cdef rsa_key key
    cdef Key _public

    # The sentinel checking code is in the cinit because I believe it is the
    # only place that it cannot be overidden.
    def __cinit__(self, input=None, **kwargs):

        cdef unsigned long size, e
        cdef PRNG prng

        if isinstance(input, (unicode, str, bytes)):
            self._from_string(input)
            return

        elif 'size' in kwargs or isinstance(input, (int, long)):
            size = kwargs.pop('size', input)
            e = kwargs.pop('e', DEFAULT_E)
            prng = kwargs.pop('prng', None)
            self._generate(size, e, prng)

        elif input is not blank_key_sentinel:
            raise Error('must supply encoded key, or new key size')

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
        # _nullify methmd.
        if self.key.N != NULL:
            rsa_free(&self.key)
    
    def __repr__(self):
        return '${'<' + '%'}s.%s %s/%s at 0x%X>' % (__name__, self.__class__.__name__,
            'private' if self.is_private else 'public',
            self.size,
            id(self),
        )

    cdef _nullify(self):
        """Mark the key as not needing to be freed.

        Use this after an error has occurred and the key automatically freed,
        but the pointers have not been reset to null.

        """
        self.key.N = NULL

    cdef _generate(self, int size, long e, PRNG prng):
        """The guts of the generate class method.

        This modifies the key in place. Be careful.

        """
        if size % 8:
            raise Error('can only generate keysizes in multiples of 8')
        self._public = None
        if prng is None:
            prng = PRNG('sprng')
        try:
            check_for_error(rsa_make_key(&prng.state, prng.idx, size / 8, e, &self.key))
        except:
            self._nullify()
            raise

    def as_string(self, type=None, format=FORMAT_PEM):
        """Build the string representation of a key.

        Both the availible formats are compatible with OpenSSL. We default to
        the same one that OpenSSL does (PEM).

        Params:
            type -- None (as is), 'private' or 'public'.
            format -- 'pem' (default), or 'der'.

        >>> k = Key(1024)

        >>> k.as_string() # doctest: +ELLIPSIS
        '-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----\\n'

        >>> k.public.as_string() # doctest: +ELLIPSIS
        '-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----\\n'

        >>> k.as_string(type='public') # doctest: +ELLIPSIS
        '-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----\\n'

        >>> isinstance(k.as_string(format='der'), bytes)
        True

        """

        if type is None:
            type = self.key.type
        elif type in type_map:
            type = type_map[type]
        else:
            raise Error('unknown key type %r' % type)

        if self.key.type == c_RSA_TYPE_PUBLIC and type == c_RSA_TYPE_PRIVATE:
            raise Error('cant get private key from public key')

        if format not in (FORMAT_DER, FORMAT_PEM):
            raise Error('unknown RSA key format %r' % format)

        # TODO: determine what size this really needs to be.
        out = PyBytes_FromStringAndSize(NULL, 4096)
        cdef unsigned long length = 4096
        check_for_error(rsa_export(out, &length, type, &self.key))

        if format == FORMAT_DER:
            return out[:length]
        return pem_encode(
            'RSA',
            'PRIVATE' if type == c_RSA_TYPE_PRIVATE else 'PUBLIC',
            out[:length]
        )

    cdef _from_string(self, input):
        """The guts of the from_string method.

        This modifies the key in place. Be careful.

        """
        self._public = None
        try:
            type, mode, input = pem_decode(input)
        except Error:
            pass
        try:
            check_for_error(rsa_import(input, len(input), &self.key))
        except:
            self._nullify()
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
        out[${repr(x)}] = buf.decode()
        % endfor
        return out

    @property
    def type(self):
        """'private' or 'public'
        
        >>> k = Key(1024)
        >>> k.type
        'private'
        >>> k.public.type
        'public'
        
        """
        return TYPE_PRIVATE if self.is_private else TYPE_PUBLIC

    @property
    def is_private(self):
        """True if this is a private key.
        
        >>> k = Key(1024)
        >>> k.is_private
        True
        >>> k.public.is_private
        False
        
        """
        return self.key.type == c_RSA_TYPE_PRIVATE

    @property
    def is_public(self):
        """True if this is a public key.
        
        >>> k = Key(1024)
        >>> k.is_public
        False
        >>> k.public.is_public
        True
        
        """
        return self.key.type == c_RSA_TYPE_PUBLIC

    @property
    def size(self):
        """The bit length of the modulus of the key.

        This will be a multiple of 8 for any key generated with this library,
        but that is not a requirement for others. (It is easy to make any
        size key with openssl, for instance.)

        >>> Key(1024).size
        1024

        """
        return mp.count_bits(self.key.N)

    def max_payload(self, padding=PAD_OAEP, hash=None):
        """The maximum length of the payload that is safe to encrypt/sign.

        Params:
            padding -- One of 'none', 'v1.5', 'oaep', or 'pss'. Defaults to 'oaep'.
            hash -- The hash that will be used. Defaults to 'sha1'.

        See tomcrypt.rsa.max_payload(...) for examples.

        """
        return max_payload(self.size, padding, hash)

    cdef Key _public_copy(self):
        """Get a copy of this key with only the public parts."""
        cdef Key copy = blank_key(self.__class__)
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
            copy._nullify()
            raise
        return copy

    @property
    def public(self):
        """A view of this key with only the public parts.

        If this is already a public key, this will be the same object.

        >>> k = Key(1024)
        >>> a = k.public
        >>> a.type
        'public'
        >>> b = k.public
        >>> a is b
        True

        """
        if self._public is None:
            if self.is_public:
                self._public = self
            else:
                self._public = self._public_copy()
        return self._public

    cdef bytes raw_crypt(self, int mode, bytes input):
        """Raw RSA encryption/decryption.

        Used by encrypt/decrypt/sign/verify when the user requests no padding.

        Decrypted text will be left-padded with NULL bytes when returned.

        Params:
            int mode -- PK_PUBLIC for encryption/verification
                        PK_PRIVATE for decryption/signing
            str input -- The text to process.
        
        """
        cdef unsigned long out_length = self.size / 8 + 1
        out = PyBytes_FromStringAndSize(NULL, out_length)
        check_for_error(rsa_exptmod(
            input, len(input),
            out, &out_length,
            mode,
            &self.key))
        return out[:out_length]

    cpdef encrypt(self, bytes input, prng=None, hash=None, padding=PAD_OAEP):
        """Encrypt some bytes.

        Parameters:
            bytes input -- The data to encrypt.
            prng -- The PRNG to use; defaults to 'sprng'.
            hash -- The Hash to use; defaults to 'sha1'.
            padding -- One of 'none', 'v1.5', or 'oaep'. Defaults to 'oaep'.

        """

        padding = conform_padding(padding)
        if padding == c_RSA_PAD_NONE:
            return self.raw_crypt(PK_PUBLIC, input)

        cdef PRNG c_prng = conform_prng(prng)
        cdef HashDescriptor c_hash = conform_hash(hash or DEFAULT_ENC_HASH)

        cdef unsigned long out_length = self.size / 8 + 1
        out = PyBytes_FromStringAndSize(NULL, out_length)
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

    cpdef decrypt(self, bytes input, hash=None, padding=PAD_OAEP):
        """Decrypt some bytes.

        Only usable on private keys.

        Parameters:
            bytes input -- The data to decrypt.
            hash -- The Hash used; defaults to 'sha1'.
            padding -- One of 'none', 'v1.5', or 'oaep'. Defaults to 'oaep'.

        """

        padding = conform_padding(padding)
        if padding == c_RSA_PAD_NONE:
            return self.raw_crypt(PK_PRIVATE, input)

        cdef HashDescriptor c_hash = conform_hash(hash or DEFAULT_ENC_HASH)

        cdef unsigned long out_length = self.size / 8 + 1
        out = PyBytes_FromStringAndSize(NULL, out_length)
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

    cpdef sign(self, bytes input, prng=None, hash=None, padding=PAD_PSS, saltlen=None):
        """Sign some bytes.

        Only usable on private keys.

        Parameters:
            bytes input -- The data to sign.
            prng -- The PRNG to use; defaults to 'sprng'.
            hash -- The Hash to use; defaults to 'sha512'.
            padding -- One of 'none', 'v1.5', or 'pss'. Defaults to 'pss'.

        """
        cdef unsigned long c_padding = conform_padding(padding)
        if c_padding == c_RSA_PAD_NONE:
            return self.raw_crypt(PK_PRIVATE, input)

        cdef PRNG c_prng = conform_prng(prng)
        cdef HashDescriptor c_hash = conform_hash(hash or DEFAULT_SIG_HASH)
        cdef unsigned long c_saltlen = conform_saltlen(self, saltlen, c_hash, padding)

        cdef unsigned long out_length = self.size / 8 + 1
        out = PyBytes_FromStringAndSize(NULL, out_length)
        check_for_error(rsa_sign_hash_ex(
            input, len(input),
            out, &out_length,
            c_padding,
            &c_prng.state, c_prng.idx,
            c_hash.idx,
            c_saltlen,
            &self.key
        ))
        return out[:out_length]

    cpdef verify(self, bytes input, bytes sig, hash=None, padding=PAD_PSS, saltlen=None):
        """Verify the signature of some bytes.

        Parameters:
            bytes input -- The signed data.
            bytes sig -- The signature.
            hash -- The Hash used; defaults to 'sha512'.
            padding -- One of 'none', 'v1.5', or 'pss'. Defaults to 'pss'.

        Returns True if the signature is valid. Raises an exception if the
        signature is the wrong format.

        """

        cdef unsigned long c_padding = conform_padding(padding)
        if c_padding == c_RSA_PAD_NONE:
            return self.raw_crypt(PK_PUBLIC, input)

        cdef HashDescriptor c_hash = conform_hash(hash or DEFAULT_SIG_HASH)
        cdef unsigned long c_saltlen = conform_saltlen(self, saltlen, c_hash, padding)

        cdef unsigned long out_length = self.size / 8 + 1
        out = PyBytes_FromStringAndSize(NULL, out_length)
        cdef int status = 0
        check_for_error(rsa_verify_hash_ex(
            sig, len(sig),
            input, len(input),
            c_padding,
            c_hash.idx,
            c_saltlen,
            &status,
            &self.key
        ))
        return bool(status)




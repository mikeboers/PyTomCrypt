import itertools

from . import TomCryptError
from .core import *
from . import meta


__all__ = ['Descriptor', 'Cipher']


# These will be run by nose.
def _internal_tests():
    for name in meta.cipher_names:
        name = meta.cipher_identfier_mapping.get(name, name)
        yield name, LTC.function('%s_test' % name, C.int)
            

class _LTC_Descriptor(C.Structure):
    _fields_ = [
    
        # Generic properties.
        ('name', C.char_p),
        ('ID', C.ubyte),
        ('min_key_size', C.int),
        ('max_key_size', C.int),
        ('block_length', C.int),
        ('default_rounds', C.int),
        
        # We don't care about these functions, but we need stubs in the
        # structure.
        ('setup', C.void_p),
        ('ecb_encrypt', C.void_p),
        ('ecb_decrypt', C.void_p),
        ('test', C.void_p),
        ('done', C.void_p),
        
        ('keysize', C.CFUNCTYPE(C.int, C.POINTER(C.int))),
        
        # There are many more functions that we don't care about, but we don't
        # need them for sizing.
    ]
    



class Descriptor(object):
    
    """Collection of information regarding a single cipher.
    
    :param str cipher: The name or index of a supported cipher.
    
    A ``Descriptor`` can also be called to construct a matching :class:`Cipher`.
    
    ::
        >>> aes = Descriptor('aes')
        >>> aes.name
        'aes'
        >>> aes.min_key_size
        16
        >>> aes.max_key_size
        32
        >>> aes.block_size
        16
        >>> aes.default_rounds
        10
        
    One can also pass a LTC idx::
    
        >>> aes2 = Descriptor(aes.idx)
        >>> aes2.name
        'rijndael'
        >>> aes2 is aes
        False
    
    or an existing descriptor::
    
        >>> aes3 = Descriptor(aes)
        >>> aes3.name
        'aes'
        >>> aes3 is aes
        False
    
    """
    
    #: Map from names and indices to ``(idx, descriptor)`` pairs.
    __name_or_index_to_internals = {}
    
    # Register the ciphers.
    register = LTC.function('register_cipher', C.int, C.POINTER(_LTC_Descriptor))
    for name in itertools.chain(['aes'], meta.cipher_names):
        name = meta.cipher_identfier_mapping.get(name, name)
        descriptor = _LTC_Descriptor.in_dll(LTC, "%s_desc" % name)
        index = register(C.byref(descriptor))
        __name_or_index_to_internals[name] = (index, descriptor)
        __name_or_index_to_internals[index] = (index, descriptor)
    del register
    
    def __init__(self, cipher):
        if isinstance(cipher, Descriptor):
            cipher = cipher.name
        self.__cipher = meta.cipher_identfier_mapping.get(cipher, cipher)
        try:
            self.__idx, self.__desc = self.__name_or_index_to_internals[self.__cipher]
        except KeyError:
            raise TomCryptError('could not find cipher %r (%r)' % (cipher, self.__cipher))
    
    @property
    def idx(self):
        """LTC internal index; not nesssesarily stable in different processes."""
        return self.__idx
    
    @property
    def name(self):
        """Canonical name of the cipher."""
        # We want a str in Python3.
        return str(self.__desc.name.decode())
    
    @property
    def min_key_size(self):
        """Minimum key size in bytes."""
        return self.__desc.min_key_size
        
    @property
    def max_key_size(self):
        """Maximum key size in bytes."""
        return self.__desc.max_key_size
        
    @property
    def block_size(self):
        """Size of a cipher block in bytes."""
        return self.__desc.block_length
    
    @property
    def default_rounds(self):
        """Default number of rounds."""
        return self.__desc.default_rounds
    
    def key_size(self, key_size):
        """Get the size of largest key that can be sliced from the given size.
        
        :param int key_size: The number of bytes of key material availible.
        :returns int: The largest number of bytes that is a valid key size.
        
        ::
            >>> aes = Descriptor('aes')
            >>> aes.key_size(16)
            16
            >>> aes.key_size(17)
            16
            >>> aes.key_size(128)
            32

        """
        key_size = C.int(key_size)
        standard_errcheck(self.__desc.keysize(C.byref(key_size)))
        return key_size.value
    
    def __call__(self, *args, **kwargs):
        kwargs['cipher'] = self.__cipher
        return Cipher(*args, **kwargs)


class Cipher(Descriptor):
    r"""All state required to use a symmetric cipher.
    
    :param bytes key: Symmetric key.
    :param bytes iv: Initialization vector; None is treated as all null bytes.
    :param str cipher: The name of the cipher to use.
    :param str mode: Cipher block chaining more to use; case insensitive.
    
    :param bytes nonce: Only for "eax" mode.
    :param bytes tweak: Only for "lrw" mode.
    :param bytes salt_key: Only for "f8" mode.
    
    ::
        >>> cipher = Cipher(b'0123456789abcdef')
        >>> cipher
        <tomcrypt.cipher.Cipher with "aes" in CTR mode at 0x...>
        >>> cipher.encrypt(b'Hello')
        b'C\xfey\xb6$'

    See :meth:`Cipher.add_header` for example of EAX mode.

    """
    def __init__(self, key, iv=None, cipher='aes', mode='ctr', **kwargs):
        super(Cipher, self).__init__(cipher)
        
        self.__mode = str(mode).lower()
        
        # Determine the state size, and create a buffer for it.
        self.__state_size = max(
            LTC.pymod.sizeof.get('symmetric_%s' % self.__mode.upper(), 0),
            LTC.pymod.sizeof.get('%s_state' % self.__mode, 0),
        )
        if not self.__state_size:
            raise TomCryptError('unknown cipher mode %r' % mode)
        self.__state = C.create_string_buffer(self.__state_size)
        
        # Conform the IV (or create one of all zeroes)
        if iv is None:
            iv = b'\0' * self.block_size
        if not isinstance(iv, bytes):
            raise TypeError('iv must be bytes')
        if len(iv) != self.block_size:
            raise TomCryptError('iv must be %d bytes; got %d' % (self.block_size, len(iv)))

        # I would rather keep the `start = getattr(...)` within the if blocks to
        # reduce the chance of a false positive.
        
        if self.__mode == 'ecb':
            # This is the most basic.
            start = getattr(LTC, '%s_start' % self.__mode)
            standard_errcheck(start(self.idx, key, C.ulong(len(key)), 0, self.__state))
            
        elif self.__mode in ('cbc', 'cfb', 'ofb'):
            # Adds an IV to ECB.
            start = getattr(LTC, '%s_start' % self.__mode)
            standard_errcheck(start(self.idx, iv, key, C.ulong(len(key)), 0, self.__state))
                
        elif self.__mode == 'ctr':
            # Adds an IV and CTR flags to ECB.
            start = getattr(LTC, '%s_start' % self.__mode)
            standard_errcheck(start(self.idx, iv, key, C.ulong(len(key)), 0, LTC.pymod.CTR_COUNTER_BIG_ENDIAN, self.__state))
        
        elif self.__mode == 'lrw':
            # Adds an IV and "tweak" to ECB.
            tweak = kwargs.get('tweak')
            if not isinstance(tweak, bytes) or len(tweak) != 16:
                raise TypeError('tweak must be 16 bytes')
            start = getattr(LTC, '%s_start' % self.__mode)
            standard_errcheck(start(self.idx, iv, key, C.ulong(len(key)), tweak, 0, self.__state))
        
        elif self.__mode == 'f8':
            # Adds an IV and "salt_key" to ECB.
            salt_key = kwargs.get('salt_key')
            if not isinstance(salt_key, bytes):
                raise TypeError('salt_key must be bytes')
            start = getattr(LTC, '%s_start' % self.__mode)
            standard_errcheck(start(self.idx, iv, key, C.ulong(len(key)), salt_key, C.ulong(len(salt_key)), 0, self.__state))
        
        elif self.__mode == 'eax':
            # Adds a "nonce" and "header" to ECB. No IV.
            nonce = kwargs.get('nonce', iv)
            if not isinstance(nonce, bytes):
                raise TypeError('nonce must be bytes')
            header = kwargs.get('header', b'')
            if not isinstance(header, bytes):
                raise TypeError('header must be bytes')
            standard_errcheck(LTC.eax_init(self.__state, self.idx,
                key, C.ulong(len(key)),
                nonce, C.ulong(len(nonce)),
                header, C.ulong(len(header)),
            ))
        
        else:
            raise TomCryptError('unknown cipher mode %r' % mode)
    
    @property
    def mode(self):
        return self.__mode
    
    def __repr__(self):
        return '<%s.%s with "%s" in %s mode at 0x%x>' % (
            self.__class__.__module__, self.__class__.__name__, self.name,
            self.mode.upper(), id(self),
        )
    
    def add_header(self, header):
        """Add the given string to the EAX header. Only for EAX mode.

        >>> cipher = aes(b'0123456789abcdef', mode='eax', nonce=b'random')
        >>> cipher.add_header(b'a header')
        >>> cipher.encrypt(b'hello')
        b'Y\\x9b\\xe5\\x87\\xcc'
        >>> cipher.done()
        b'A(|\\x9f@I#\\x0f\\x93\\x90Z,\\xb5A\\x9bN'

        >>> cipher = aes(b'0123456789abcdef', mode='eax', nonce=b'random', header=b'a header')
        >>> cipher.decrypt(b'Y\\x9b\\xe5\\x87\\xcc')
        b'hello'
        >>> cipher.done()
        b'A(|\\x9f@I#\\x0f\\x93\\x90Z,\\xb5A\\x9bN'

        """
        if not isinstance(header, bytes):
            raise TypeError('header must be bytes')
        if self.__mode != 'eax':
            raise TomCryptError('not EAX mode')
        standard_errcheck(LTC.eax_addheader(self.__state, header, len(header)))
    
    def get_iv(self):
        """Returns the current IV, for modes that use it.
        
        E.g.::
            >>> cipher = aes(b'0123456789abcdef', b'ThisWillSetTheIV')
            >>> cipher.get_iv()
            b'ThisWillSetTheIV'
        
        This is also accessable as a property::
            >>> cipher.iv
            b'ThisWillSetTheIV'
        
        """
        
        try:
            get_iv = getattr(LTC, '%s_getiv' % self.__mode)
        except AttributeError:
            # Not raising here so that contexts aren't chained in Python3.
            get_iv = None
        if not get_iv:
            raise TomCryptError("%r mode does not use an IV" % self.__mode)
        
        length = C.ulong(self.block_size)
        iv = C.create_string_buffer(self.block_size)
        standard_errcheck(get_iv(iv, C.byref(length), C.byref(self.__state)))
        return iv[:length.value]
    
    def set_iv(self, iv):
        """ Sets the current IV, for modes that use it.

        See the LibTomCrypt manual section 3.4.6 for what, precisely, this
        function will do depending on the chaining mode.
        
        E.g.::
            >>> cipher = aes(b'0123456789abcdef')
            >>> cipher.set_iv(b'ThisWillSetTheIV')
            >>> cipher.encrypt(b'hello')
            b'\\xe2\\xef\\xc5\\xe6\\x9e'

        This is also accessable as a property::
            >>> cipher = aes(b'0123456789abcdef')
            >>> cipher.iv = b'ThisWillSetTheIV'
            >>> cipher.encrypt(b'hello')
            b'\\xe2\\xef\\xc5\\xe6\\x9e'
        
        """
        
        try:
            set_iv = getattr(LTC, '%s_setiv' % self.__mode)
        except AttributeError:
            # Not raising here so that contexts aren't chained in Python3.
            set_iv = None
        if not set_iv:
            raise TomCryptError("%r mode does not use an IV" % self.__mode)
        
        if not isinstance(iv, bytes):
            raise TypeError('iv must be bytes')
        if len(iv) != self.block_size:
            raise TomCryptError('iv must be %d bytes; got %d' % (self.block_size, len(iv)))
        standard_errcheck(set_iv(iv, len(iv), C.byref(self.__state)))
    
    iv = property(get_iv, set_iv)
    
    def encrypt(self, input):
        r"""Encrypt a string.
        
        :param bytes input: The string to encrypt. Unless in CTR mode this must
            be a multiple of the cipher's block length.
        :returns bytes:
        
        ::
            >>> cipher = Cipher(b'0123456789abcdef', cipher='aes', mode='ctr')
            >>> cipher.encrypt(b'this is a message')
            b'\x7f\xf3|\xa9k-\xd3\xd5t=\xa2\xa1\xb3lT\xb2d'
        
        """
        return self._crypt(True, input)
    
    def decrypt(self, input):
        r"""Decrypt a string.
        
        :param bytes input: The string to decrypt. Unless in CTR mode this must
            be a multiple of the cipher's block length.
        ::
            >>> cipher = Cipher(b'0123456789abcdef', cipher='aes', mode='ctr')
            >>> cipher.decrypt(b'\x7f\xf3|\xa9k-\xd3\xd5t=\xa2\xa1\xb3lT\xb2d')
            b'this is a message'
        
        """
        return self._crypt(False, input)
    
    def _crypt(self, encrypt, input):
        
        if not isinstance(input, bytes):
            raise TypeError('input must be bytes')

        output = C.create_string_buffer(len(input))
        func = getattr(LTC, '%s_%scrypt' % (self.__mode, 'en' if encrypt else 'de'))
        if self.__mode == 'eax':
            standard_errcheck(func(self.__state, input, output, C.ulong(len(input))))
        else:
            standard_errcheck(func(input, output, C.ulong(len(input)), self.__state))
        
        # Must explicitly slice it to make sure we get null bytes.
        return output[:len(input)]
        

    def done(self):
        """Return authentication tag for EAX mode.

        See Cipher.add_header(...) for example.

        """

        if self.__mode != 'eax':
            raise TomCryptError('not EAX mode')
        
        length = C.ulong(self.block_size)
        output = C.create_string_buffer(length.value)
        standard_errcheck(LTC.eax_done(self.__state, output, C.byref(length)))
        return output[:length.value]


#: A set of all of the supported cipher names.
names = set(meta.cipher_names)
names.add('aes')

# Preconstruct descriptors for each cipher.
for name in names:
    globals()[meta.cipher_identfier_mapping.get(name, name)] = Descriptor(name)
del name



        
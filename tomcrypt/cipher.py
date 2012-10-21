import itertools

from . import Error
from .core import *
from . import meta


# These will be run by nose.
def _internal_tests():
    for name in meta.cipher_names:
        yield name, LTC.function('%s_test' % name, C.int)
            

class _LTC_Descriptor(C.Structure):
    _fields_ = [
        ('name', C.char_p),
        ('ID', C.ubyte),
        ('min_key_size', C.int),
        ('max_key_size', C.int),
        ('block_length', C.int),
        ('default_rounds', C.int),
        
        ('setup', C.void_p),
        ('ecb_encrypt', C.void_p),
        ('ecb_decrypt', C.void_p),
        ('test', C.void_p),
        ('done', C.void_p),
        
        ('keysize', C.CFUNCTYPE(C.int, C.POINTER(C.int))),
        
        # There are a bunch of encrypt/decrypt functions here as well that we
        # really don't care about.
    ]
    

# Register the ciphers. ``_cipher_internals`` maps from names to
# ``(index, desciptor)`` tuples.
_register_cipher = LTC.function('register_cipher', C.int, C.POINTER(_LTC_Descriptor))
_cipher_internals = {}
for cipher_name in itertools.chain(['aes'], meta.cipher_names):
    descriptor = _LTC_Descriptor.in_dll(LTC, "%s_desc" % cipher_name)
    index = _register_cipher(C.byref(descriptor))
    _cipher_internals[cipher_name] = (index, descriptor)


class Descriptor(object):
    """LibTomCrypt descriptor of a symmetric cipher.
    
    Can be called as convenience to calling Cipher, passing the cipher name
    via kwargs.
    
    ::
        >>> desc = Descriptor('aes') # Same as tomcrypt.cipher.aes.
        >>> desc.name
        'aes'
    
    """
    
    def __init__(self, cipher):
        self.__cipher = {
            '3des': 'des3',
            'seed': 'kseed',
            'safer+': 'saferp',
        }.get(cipher, cipher)
        try:
            self.__idx, self.__desc = _cipher_internals[self.__cipher]
        except KeyError:
            raise Error('could not find cipher %r (%r)' % (cipher, self.__cipher))
    
    @property
    def idx(self):
        return self.__idx
    
    @property
    def name(self):
        """Cipher name.
        
        ::
            >>> Descriptor('aes').name
            'aes'
        """
        return self.__desc.name
        
    @property
    def min_key_size(self):
        """Cipher minimum key size in bytes.
        
        ::
            >>> Descriptor('aes').min_key_size
            16
        """
        return self.__desc.min_key_size
        
    @property
    def max_key_size(self):
        """Cipher maximum key size in bytes.
        
        ::
            >>> Descriptor('aes').max_key_size
            32
        """
        return self.__desc.max_key_size
        
    @property
    def block_size(self):
        """Size of a cipher block in bytes.
        
        ::
            >>> Descriptor('aes').block_size
            16
        """
        return self.__desc.block_length
    
    @property
    def default_rounds(self):
        """Default number of rounds.
        
        ::
            >>> Descriptor('aes').default_rounds
            10
        """
        return self.__desc.default_rounds
    
    def key_size(self, key_size):
        """The largest key that can be sliced from a string of the given size.
        
        ::
            >>> aes = Descriptor('aes')
            >>> aes.key_size(16)
            16
            >>> aes.key_size(17)
            16
            >>> aes.key_size(128)
            32

        """
        out = C.int(key_size)
        standard_errcheck(self.__desc.keysize(C.byref(out)))
        return out.value
    
    def __call__(self, *args, **kwargs):
        kwargs['cipher'] = self.__cipher
        return Cipher(*args, **kwargs)


class Cipher(Descriptor):
    """All state required to encrypt/decrypt with a symmetric cipher.
    
    :param bytes key: Symmetric key.
        bytes key -- Symmetric key.
        bytes iv -- Initialization vector; None is treated as all null bytes.
        str cipher -- The name of the cipher to use; defaults to "aes".
        str mode -- Cipher block chaining more to use; defaults to "ctr".
    
    Mode Specific Parameters:
        bytes nonce -- Only for "eax" mode.
        bytes tweak -- Only for "lrw" mode.
        bytes salt_key -- Only for "f8" mode.
    
    ::
        >>> cipher = Cipher(b'0123456789abcdef', b'0123456789abcdef', cipher='aes', mode='ctr')
        >>> cipher
        <tomcrypt.cipher.Cipher with "aes" in CTR mode at 0x...>

    See Cipher.add_header(...) for example of EAX mode.

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
            raise Error('no mode %r' % mode)
        self.__state = C.create_string_buffer(self.__state_size)
        
        # Conform the IV (or create a one of all zeroes)
        if iv is None:
            iv = b'\0' * self.block_size
        if not isinstance(iv, bytes) or len(iv) != self.block_size:
            raise Error('iv must be %d bytes; got %r' % (self.block_size, iv))

        if self.__mode in meta.cipher_simple_modes:
            start = LTC.function('%s_start' % self.__mode, C.int,
                C.int, # idx
                C.char_p, # IV
                C.char_p, # key
                C.int, # len(key)
                C.int, # number of rounds
                C.void_p, # state
                errcheck=True
            )
            start(self.idx, iv, key, len(key), 0, self.__state)
            
        elif self.__mode == 'ecb':
            start = LTC.function('%s_start' % self.__mode, C.int,
                C.int, # idx
                C.char_p, # key
                C.int, # len(key)
                C.int, # number of rounds
                C.void_p, # state
                errcheck=True
            )
            start(self.idx, key, len(key), 0, self.__state)
                
        elif self.__mode == 'ctr':
            start = LTC.function('%s_start' % self.__mode, C.int,
                C.int, # idx
                C.char_p, # IV
                C.char_p, # key
                C.int, # len(key)
                C.int, # number of rounds
                C.int, # CTR flags
                C.void_p, # state
                errcheck=True,
            )
            start(self.idx, iv, key, len(key), 0, LTC.pymod.CTR_COUNTER_BIG_ENDIAN, self.__state)
        
        else:
            raise Error('Unknown cipher mode %r' % mode)
    
    @property
    def mode(self):
        return self.__mode
    
    def __repr__(self):
        return '<%s.%s with "%s" in %s mode at 0x%x>' % (
            self.__class__.__module__, self.__class__.__name__, self.name,
            self.mode.upper(), id(self),
        )
    
    def encrypt(self, input):
        """Encrypt a string.
        
        ::
            >>> cipher = Cipher(b'0123456789abcdef', cipher='aes', mode='ctr')
            >>> cipher.encrypt(b'this is a message')
            b'\\x7f\\xf3|\\xa9k-\\xd3\\xd5t=\\xa2\\xa1\\xb3lT\\xb2d'
        
        """
        return self._crypt(True, input)
    
    def decrypt(self, input):
        """Decrypt a string.
        
        ::
            >>> cipher = Cipher(b'0123456789abcdef', cipher='aes', mode='ctr')
            >>> cipher.decrypt(b'\\x7f\\xf3|\\xa9k-\\xd3\\xd5t=\\xa2\\xa1\\xb3lT\\xb2d')
            b'this is a message'
        
        """
        return self._crypt(False, input)
    
    def _crypt(self, encrypt, input):
        
        if not isinstance(input, bytes):
            raise TypeError('input must be bytes')

        func = LTC.function('%s_%scrypt' % (self.__mode, 'en' if encrypt else 'de'), C.int,
            C.char_p, # Input.
            C.char_p, # Output.
            C.ulong, # Length.
            C.void_p, # State.
            errcheck=True,
        )
        output = C.create_string_buffer(len(input))
        func(input, output, len(input), self.__state)
        
        # Must explicitly slice it to make sure we get null bytes.
        return output[:len(input)]
        

names = set(meta.cipher_names)
names.add('aes')

for name in names:
    globals()[name] = Descriptor(name)
del name



        
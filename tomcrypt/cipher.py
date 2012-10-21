import itertools

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
        cipher = {
            'des3': '3des',
            'kseed': 'seed',
            'saferp': 'safer+',
        }.get(cipher, cipher)
        
        try:
            self.__idx, self.__desc = _cipher_internals[cipher]
        except KeyError:
            raise Error('could not find cipher %r' % cipher)
    
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
    
        
from base64 import b16encode

from . import TomCryptError
from .cipher import Descriptor as CipherDescriptor
from .core import *
from .hash import Descriptor as HashDescriptor
from . import meta


__all__ = ['MAC']


# These will be run by nose.
def _internal_tests():
    for name in meta.mac_names:
        yield name, LTC.function('%s_test' % name, C.int)


class _HMAC_State(C.Structure):
    _fields_ = [
        ('md', C.ubyte * LTC.pymod.sizeof['hash_state']),
        ('hash', C.int),
        ('hashstate', C.ubyte * LTC.pymod.sizeof['hash_state']),
        ('key', C.void_p),
    ]


class MAC(object):
    """Calculator of keyed hashes.

    Parameters:
        str mode -- What type of mac. One of 'hmac', 'omac', 'pmac', or 'xcbc'.
        idx -- What cipher/hash to use. Either a name or descriptor.
        bytes key -- The key.
        bytes input -- Initial data.

    >>> mac = MAC('hmac', 'md5', b'secret') # or hmac('md5', b'secret')
    >>> mac = MAC('omac', 'aes', b'0123456789abcdef') # or omac(...)
    >>> mac = MAC('pmac', 'aes', b'0123456789abcdef') # or pmac(...)
    >>> mac = MAC('xcbc', 'aes', b'0123456789abcdef') # or xcbc(...)

    """
    
    def __init__(self, mode, hash_or_cipher, key, input=b''):
        
        self._state = None
        
        self._mode = str(mode).lower()
        if self._mode not in meta.mac_names:
            raise TomCryptError('no MAC %r' % mac)
        
        if not isinstance(key, bytes):
            raise TypeError('key must be bytes')
        
        state_size = LTC.pymod.sizeof['%s_state' % self._mode]
        self._state = C.create_string_buffer(state_size)
        
        if self.uses_hash:
            self._desc = HashDescriptor(hash_or_cipher)
        else:
            self._desc = CipherDescriptor(hash_or_cipher)
        
        self._key = key
        
        init = getattr(LTC, '%s_init' % self._mode)
        standard_errcheck(init(self._state, self._desc._idx, key, C.ulong(len(key))))
        
        if input:
            self.update(input)
    
    @property
    def mode(self):
        return self._mode
    
    @property
    def uses_hash(self):
        return self._mode in meta.hash_macs
    
    @property
    def uses_cipher(self):
        return self._mode not in meta.hash_macs
    
    def __del__(self):
        # HMAC is the only one that has anything we need to manually free.
        if self._mode == 'hmac' and self._state is not None:
            LTC.free_hmac_state(self._state)
    
    def __repr__(self):
        return '<%s.%s of %s using %s at 0x%x>' % (
            self.__class__.__module__, self.__class__.__name__, self.mode,
            self.desc.name, id(self))
    
    def update(self, input):
        """Add more data to the mac.

        >>> mac = hmac('md5', b'secret')
        >>> mac.update(b'message')
        >>> mac.hexdigest()
        '7e0d0767775312154ba16fd3af9771a2'

        """
        if not isinstance(input, bytes):
            raise TypeError('input must be bytes')
        
        process = getattr(LTC, '%s_process' % self._mode)
        standard_errcheck(process(self._state, input, C.ulong(len(input))))
    
    def digest(self, length=None):
        """Return binary digest.

        >>> mac = hmac('md5', b'secret', b'message')
        >>> mac.digest()
        b'~\\r\\x07gwS\\x12\\x15K\\xa1o\\xd3\\xaf\\x97q\\xa2'

        """
        if length is None:
            if self.uses_hash:
                length = self._desc.digest_size
            else:
                length = self._desc.block_size
        
        
        # Make a copy of the hmac state and all of it's parts. We need to do
        # this because the *_done function mutates the state. The key is
        # deallocated so we aren't causing a memory leak here.
        
        state_size = LTC.pymod.sizeof.get('%s_state' % self._mode)
        state = C.create_string_buffer(state_size)
        state[:] = self._state
        
        if self._mode == 'hmac':
            LTC.copy_hmac_state(state, self._state, self._desc.block_size)
        
        output = C.create_string_buffer(length)
        length = C.ulong(length)
        
        done = getattr(LTC, '%s_done' % self._mode)
        standard_errcheck(done(state, output, C.byref(length)))
        return output[:length.value]
    
    def hexdigest(self, length=None):
        """Return hex-encoded string of digest.

        >>> mac = hmac('md5', b'secret', b'message')
        >>> mac.hexdigest()
        '7e0d0767775312154ba16fd3af9771a2'

        """

        return str(b16encode(self.digest(length)).decode().lower())
    
    def copy(self):
        """Get a copy of the mac state.

        >>> a = hmac('md5', b'secret', b'message')
        >>> b = a.copy()
        >>> b.update(b'some more')
        >>> b.hexdigest()
        'e0cdc5e1d7af04f800b0e0f0ceee588a'
        >>> a.hexdigest()
        '7e0d0767775312154ba16fd3af9771a2'

        """
        copy = self.__class__(self._mode, self._desc._idx, self._key)
        
        state_size = LTC.pymod.sizeof.get('%s_state' % self._mode)
        copy._state = C.create_string_buffer(state_size)
        copy._state[:] = self._state
        
        if self._mode == 'hmac':
            LTC.copy_hmac_state(C.byref(copy._state), C.byref(self._state), self._desc.block_size)
        
        return copy


hash_macs = set(meta.hash_macs)
cipher_macs = set(meta.cipher_macs)
names = set(meta.mac_names)

# Preconstruct descriptors for each cipher.
def _builder(name):
    def _shortcut(*args, **kwargs):
        return MAC(name, *args, **kwargs)
    _shortcut.__name__ = name
    return _shortcut
for name in names:
    globals()[name] = _builder(name)
    __all__.append(name)
del name
del _builder


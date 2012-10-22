import itertools
import base64

from . import TomCryptError
from .core import *
from . import meta


__all__ = ['Descriptor', 'Hash']


# These will be run by nose.
def _internal_tests():
    for name in meta.hash_names:
        yield name, LTC.function('%s_test' % name, C.int)
            

class _LTC_Descriptor(C.Structure):
    _fields_ = [
    
        # Generic properties.
        ('name', C.char_p),
        ('ID', C.ubyte),
        ('hashsize', C.ulong),
        ('blocksize', C.int),
        ('OID', C.ulong * 16),
        ('OIDlen', C.ulong),
        
        # Functions.
        ('init', C.CFUNCTYPE(C.void, C.void_p)),
        ('process', C.CFUNCTYPE(C.int, C.void_p, C.char_p, C.ulong)),
        ('done', C.CFUNCTYPE(C.int, C.void_p, C.char_p)),
        
        # We don't care about the rest.
    ]


class Descriptor(object):
    
    """
    
    >>> md5 = Descriptor('md5')
    >>> md5.name
    'md5'
    >>> md5.digest_size
    16
    >>> md5.block_size
    64
    
    """
    
    #: Map from hash names to ``(idx, descriptor)`` pairs.
    _name_to_descriptor = {}
    
    # Register the hashes.
    register = LTC.function('register_hash', C.int, C.POINTER(_LTC_Descriptor))
    for name in meta.hash_names:
        descriptor = _LTC_Descriptor.in_dll(LTC, "%s_desc" % name)
        index = register(C.byref(descriptor))
        _name_to_descriptor[name] = (index, descriptor)
    del register
    
    def __init__(self, hash):
        self.__hash = hash
        try:
            self.__idx, self._desc = self._name_to_descriptor[hash]
        except KeyError:
            raise TomCryptError('could not find hash %r' % hash)
    
    @property
    def name(self):
        """Canonical name of this hash."""
        # The extra str is so that Python 2 will return a byte string.
        return str(self._desc.name.decode())

    @property
    def digest_size(self):
        """Size of final digest, in bytes."""
        return int(self._desc.hashsize)

    @property
    def block_size(self):
        """Internal block size of this hash, in bytes."""
        return int(self._desc.blocksize)

    def __repr__(self):
        return '<%s.%s of %s>' % (
            self.__class__.__module__, self.__class__.__name__, self.name
        )
    
    def __call__(self, *args, **kwargs):
        """Initialize a hash state.

        This is a convenience for constructing Hash objects.

        >>> hash = md5(b'message')
        >>> hash.hexdigest()
        '78e731027d8fd50ed642340b7c9a63b3'

        """
        if self.name == 'chc':
            return CHC(*args, **kwargs)
        return Hash(self.name, *args, **kwargs)
    
    def digest(self, input):
        """Return digest for a single string.

        This is a convenience for constructing a Hash object and calling
        hexdigest on it.

        >>> md5.digest(b'message')
        b'x\\xe71\\x02}\\x8f\\xd5\\x0e\\xd6B4\\x0b|\\x9ac\\xb3'

        """
        return self(input).digest()
    
    def hexdigest(self, input):
        """Return hexdigest for a single string.

        This is a convenience for constructing a Hash object and calling
        hexdigest on it.

        >>> md5.hexdigest(b'message')
        '78e731027d8fd50ed642340b7c9a63b3'

        """

        return self(input).hexdigest()


class Hash(Descriptor):
    
    def __init__(self, hash, input=b''):
        super(Hash, self).__init__(hash)
        self.__state = C.create_string_buffer(LTC.pymod.MAXBLOCKSIZE)
        standard_errcheck(self._desc.init(self.__state))
        if input:
            self.update(input)
    
    def __repr__(self):
        return '<%s.%s of %s at 0x%x>' % (
            self.__class__.__module__, self.__class__.__name__, self.name,
            id(self))
    
    def update(self, input):
        """Add more data to the digest.

        >>> hash = md5()
        >>> hash.update(b'message')
        >>> hash.hexdigest()
        '78e731027d8fd50ed642340b7c9a63b3'

        """
        standard_errcheck(self._desc.process(self.__state, input, C.ulong(len(input))))
    
    def digest(self):
        """Return binary digest.

        >>> hash = md5(b'message')
        >>> hash.digest()
        b'x\\xe71\\x02}\\x8f\\xd5\\x0e\\xd6B4\\x0b|\\x9ac\\xb3'

        """
        
        # Copy the state.
        state = C.create_string_buffer(LTC.pymod.MAXBLOCKSIZE)
        state[:] = self.__state
        
        output = C.create_string_buffer(self.digest_size)
        standard_errcheck(self._desc.done(self.__state, output))
        return output[:self.digest_size]
    
    def hexdigest(self):
        """Return hex-encoded string of digest.

        >>> hash = md5(b'message')
        >>> hash.hexdigest()
        '78e731027d8fd50ed642340b7c9a63b3'

        """
        return str(base64.b16encode(self.digest()).decode().lower())
    
    def copy(self):
        """Get a copy of the hash state.

        >>> a = md5(b'message')
        >>> b = a.copy()
        >>> b.update(b'some more')
        >>> b.hexdigest()
        'd62b5837649450564c7fc65d1ab2ef85'
        >>> a.hexdigest()
        '78e731027d8fd50ed642340b7c9a63b3'

        """
        # HACK ALERT: This is only safe because we have read through the
        # source of all the provided hashes and determined that there are no
        # shared pointers, etc.
        copy = self.__class__(self.name)
        copy.__state[:] = self.__state
        return copy
        
        
        
#: A set of all of the supported hash names.
names = set(meta.hash_names)

# Preconstruct descriptors for each hash.
for name in names:
    globals()[name] = Descriptor(name)
del name

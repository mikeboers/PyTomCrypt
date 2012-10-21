# vim: set syntax=pyrex

from base64 import b16encode

from tomcrypt._core cimport *
from tomcrypt._core import Error

from tomcrypt.cipher cimport Descriptor as CipherDescriptor
from tomcrypt.cipher cimport get_cipher_idx

# Just making sure everything is registered.
import tomcrypt.cipher

def test_library():
    """Run internal libtomcrypt hash tests.
    
    >>> test_library()
    True
    
    """
    % for name in hash_names:
    check_for_error(${name}_desc.test())
    % endfor
    return True


cdef int max_hash_idx = -1    
% for name in hash_names:
max_hash_idx = max(max_hash_idx, register_hash(&${name}_desc))
% endfor


cdef get_hash_idx(input):
    cdef int idx = -1
    # (unicode, str) is a standin for basestring, which doesn't exist in 3.
    # This line has the effect of accepting only strings in 3, and
    # bytes/strings in 2.
    if isinstance(input, (unicode, str)):
        b_input = input.encode()
        idx = find_hash(b_input)
    elif isinstance(input, Descriptor):
        idx = input.idx
    if idx < 0 or idx > max_hash_idx:
        raise Error('could not find hash %r' % input)
    return idx
    

cdef class Descriptor(object):
    """LibTomCrypt descriptor of a hash function.
    
    Can be called as convenience to calling Hash, passing the hash name
    via kwargs.

    >>> md5 = Descriptor('md5') # Same as tomcrypt.hash.md5.
    
    """
    def __init__(self, hash):
        self.idx = get_hash_idx(hash)
        self.desc = &hash_descriptors[self.idx]
        if not isinstance(self, CHC) and self.name == 'chc_hash':
            raise Error('cannot build chc descriptor; use tomcrypt.hash.CHC')

    @property
    def name(self):
        """Name of this hash.

        >>> md5.name
        'md5'

        """
        # The extra str is so that Python 2 will return a byte string.
        return str(self.desc.name.decode())

    @property
    def digest_size(self):
        """Size of final digest, in bytes.

        >>> md5.digest_size
        16

        """
        return int(self.desc.digest_size)

    @property
    def block_size(self):
        """Internal block size of this hash, in bytes.

        >>> md5.block_size
        64

        """
        return int(self.desc.block_size)

    def __repr__(self):
        return ${repr('<%s.%s of %s>')} % (
            self.__class__.__module__, self.__class__.__name__, self.name)
    
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


cdef class Hash(Descriptor):
    """All state required to digest messages with a given hash function.

    The API of this class has been designed to be a drop-in replacement for
    the standard library's hashlib.

    For CHC hashes see CHC class.

    Parameters:
        str hash -- The name of the hash fuction, or a hash Descriptor.
        bytes input -- Initial input.

    >>> hash = Hash('md5', b'message')

    """
    
    cdef hash_state state
    cdef bint allocated
    
    def __init__(self, hash, bytes input=b''):
        self.allocated = False
        Descriptor.__init__(self, hash)
        self.allocated = True
        # This does not return an error value, so we don't check.
        self.desc.init(&self.state)
        self.update(input)
    
    def __dealloc__(self):
        cdef unsigned char *out
        if self.allocated:
            out = <unsigned char *> malloc(MAXBLOCKSIZE)
            self.desc.done(&self.state, out)
            free(out)
        
    def __repr__(self):
        return ${repr('<%s.%s of %s at 0x%x>')} % (
            self.__class__.__module__, self.__class__.__name__, self.name,
            id(self))       

    cpdef update(self, bytes input):
        """Add more data to the digest.

        >>> hash = md5()
        >>> hash.update(b'message')
        >>> hash.hexdigest()
        '78e731027d8fd50ed642340b7c9a63b3'

        """
        check_for_error(self.desc.process(&self.state, input, len(input)))
    
    cpdef digest(self):
        """Return binary digest.

        >>> hash = md5(b'message')
        >>> hash.digest()
        b'x\\xe71\\x02}\\x8f\\xd5\\x0e\\xd6B4\\x0b|\\x9ac\\xb3'

        """
        cdef hash_state state
        memcpy(&state, &self.state, sizeof(hash_state))
        out = PyBytes_FromStringAndSize(NULL, self.desc.digest_size)
        check_for_error(self.desc.done(&state, out))
        return out
    
    cpdef hexdigest(self):
        """Return hex-encoded string of digest.

        >>> hash = md5(b'message')
        >>> hash.hexdigest()
        '78e731027d8fd50ed642340b7c9a63b3'

        """
        return str(b16encode(self.digest()).decode().lower())
    
    cpdef copy(self):
        """Get a copy of the hash state.

        >>> a = md5(b'message')
        >>> b = a.copy()
        >>> b.update(b'some more')
        >>> b.hexdigest()
        'd62b5837649450564c7fc65d1ab2ef85'
        >>> a.hexdigest()
        '78e731027d8fd50ed642340b7c9a63b3'

        """
        cdef Hash copy = self.__class__(self.name)
        # HACK ALERT: This is only safe because we have read through the
        # source of all the provided hashes and determined that there are no
        # shared pointers, etc.
        memcpy(&copy.state, &self.state, sizeof(hash_state))
        return copy
    

cdef class CHC(Hash):
    """Hash state for CHC hash function, and Descriptor standin.

    Parameters:
        str cipher -- Name of cipher to use; all usable cipher names are stored
            in `chc_ciphers`.
        bytes input -- Initial message input.

    >>> hash = chc('aes', b'message')
        
    The Descriptor of the cipher being used is availible as the `cipher`
    attribute.

    >>> hash.cipher.name
    'aes'

    """

    cdef readonly CipherDescriptor cipher
    
    def __init__(self, cipher, bytes input=b''):
        self.cipher = CipherDescriptor(cipher)
        self.assert_chc_cipher()
        Hash.__init__(self, 'chc_hash', input)
    
    def __repr__(self):
        return ${repr('<%s.%s of %s at 0x%x>')} % (
            self.__class__.__module__, self.__class__.__name__, self.cipher.name,
            id(self))
            
    cdef inline assert_chc_cipher(self):
        # This is kinda ugly to do EVERY time, but I haven't been able to get
        # around it. Whoops.
        check_for_error(chc_register(self.cipher.idx))
        # self.desc.block_size  = self.cipher.desc.block_size
        # self.desc.digest_size = self.cipher.desc.block_size
    
    @property
    def name(self):
        """Name of this hash function; always 'chc'.

        >>> chc('aes').name
        'chc'

        """
        return 'chc'
    
    @property
    def block_size(self):
        """Internal block size of CHC hash, in bytes; same as cipher block_size.

        >>> chc('aes').block_size
        16

        """
        return self.cipher.block_size
    
    @property
    def digest_size(self):
        """Final digest size, in bytes; same as cipher block_size.

        >>> chc('aes').digest_size
        16

        """
        return self.cipher.block_size
    
    cpdef update(self, bytes input):
        """Add more data to the digest.

        >>> hash = chc('aes')
        >>> hash.update(b'message')
        >>> hash.hexdigest()
        '2597c4c0b4411482f8a7798c5a015626'

        """

        self.assert_chc_cipher()
        Hash.update(self, input)
    
    # This is only different cause it is taking the cipher block size, and
    # making sure the right hash is still registered.
    cpdef digest(self):
        """Return binary digest.

        >>> hash = chc('aes', b'message')
        >>> hash.digest()
        b'%\\x97\\xc4\\xc0\\xb4A\\x14\\x82\\xf8\\xa7y\\x8cZ\\x01V&'

        """
        cdef hash_state state
        memcpy(&state, &self.state, sizeof(hash_state))
        out = PyBytes_FromStringAndSize(NULL, self.cipher.desc.block_size)
        self.assert_chc_cipher()
        check_for_error(self.desc.done(&state, out))
        return out
                

names = ${repr(set(hash_names))}


% for name in hash_names:
% if name != 'chc':
${name} = Descriptor(${repr(name)})
% endif
% endfor
chc = CHC


# For drop-in compatibility with hashlib.
def new(name, *args, **kwargs):
    """Construct a hash by name.

    >>> hash = new('md5', b'message')
    >>> hash.hexdigest()
    '78e731027d8fd50ed642340b7c9a63b3'

    >>> hash = new('chc', 'aes', b'message')
    >>> hash.hexdigest()
    '2597c4c0b4411482f8a7798c5a015626'

    """
    if name == 'chc':
        return CHC(*args, **kwargs)
    return Hash(name, *args, **kwargs)


chc_ciphers = []
for name in tomcrypt.cipher.names:
    desc = tomcrypt.cipher.Descriptor(name)
    try:
        if desc.block_size == desc.key_size(desc.block_size):
            chc_ciphers.append(name)
    except tomcrypt.Error:
        pass


cdef Descriptor conform_hash(x):
    """Turn a user supplied hash into a Descriptor."""
    if isinstance(x, Descriptor):
        return x
    return Descriptor(x)


# Clean up the global namespace.
del tomcrypt
del name
del desc

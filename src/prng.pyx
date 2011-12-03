# vim: set syntax=pyrex

from tomcrypt._core cimport *
from tomcrypt._core import Error

# Just to make sure everything is registered.
import tomcrypt.cipher
import tomcrypt.hash

cdef int max_prng_idx = -1
% for name in prng_names:
max_prng_idx = max(max_prng_idx, register_prng(&${name}_desc))
% endfor

cdef get_prng_idx(input):
    idx = -1
    # (unicode, str) it to take `native` string in both versions
    if isinstance(input, (unicode, str)):
        b_input = input.encode()
        idx = find_prng(b_input)
    elif isinstance(input, PRNG):
        idx = input.idx
    if idx < 0 or idx > max_prng_idx:
        raise Error('could not find prng %r' % input)
    return idx


def test_library():
    """Run internal libtomcrypt prng tests.
    
    >>> test_library()
    True
    
    """  
    % for name in prng_names:
    check_for_error(${name}_desc.test())
    % endfor
    return True


cdef class PRNG(object):
    """A pseudo-random number generator.
    
    Generates streams of pseudo-random bytes. Must be seeded, but can be
    auto-seeded from the operating system (e.g. /dev/urandom on *nix).

    See tomcrypt.prng.names for a list of availible PRNG names.

    >>> list(sorted(names))
    ['fortuna', 'rc4', 'sober128', 'sprng', 'yarrow']
    
    >>> # Manual seeding:
    >>> myprng = PRNG('yarrow') # or yarrow()
    >>> myprng.add_entropy(b'from a random oracle')
    >>> myprng.read(8)
    b'\\xa5\\x0f\\xc3\\x84\\xd9\\xb1LK'

    >>> # Auto-seeding (with 1KB of data from the system PRNG):
    >>> myprng = PRNG('yarrow', 1024)
    >>> myprng.read(8) # doctest: +ELLIPSIS
    b'...'

    """

    def __init__(self, prng, entropy=None):
        self.idx = get_prng_idx(prng)
        self.desc = &prng_descriptors[self.idx]
        check_for_error(self.desc.start(&self.state))
        self.ready = False
        if isinstance(entropy, int):
            self.auto_seed(entropy)
        elif isinstance(entropy, bytes):
            self.add_entropy(entropy)
        elif entropy is not None:
            raise TypeError('entropy must be int or bytes; got %r' % entropy)
    
    def __dealloc__(self):
        self.desc.done(&self.state)
    
    @property
    def name(self):
        """The name of the PRNG.

        >>> yarrow().name
        'yarrow'
        >>> fortuna().name
        'fortuna'
        >>> sprng().name
        'sprng'

        """
        return str(self.desc.name.decode())

    @property
    def export_size(self):
        """The size of the output of the PRNG.get_state() method.

        >>> yarrow().export_size
        64

        """
        return int(self.desc.export_size)
    
    def auto_seed(self, unsigned long length):
        """Seed this PRNG from the system PRNG.

        >>> myrng = yarrow()
        >>> myrng.auto_seed(1024) # 1KB of random data.
        
        """
        entropy = PyBytes_FromStringAndSize(NULL, length)
        read_len = rng_get_bytes(entropy, length, NULL)
        if read_len != length:
            raise Error('only read %d of requested %d' % (read_len, length))
        self.add_entropy(entropy)
        
    def add_entropy(self, bytes input):
        """Stir in some bytes to the entropy pool.

        Some PRNGs have length restrictions on entropy. "fortuna", for instance
        will only accept 32 bytes.

        >>> myrng = yarrow()
        >>> myrng.add_entropy(b'from a random oracle')
        >>> myrng.read(8)
        b'\\xa5\\x0f\\xc3\\x84\\xd9\\xb1LK'

        """
        if self.name == 'fortuna' and len(input) > 32:
            raise Error('can only add 32 bytes of entropy to fortuna')
        check_for_error(self.desc.add_entropy(input, len(input), &self.state))
        self.ready = False
    
    cdef _autoready(self):
        if not self.ready:
            check_for_error(self.desc.ready(&self.state))
            self.ready = True

    def read(self, int length):
        """Retrieve binary data from the PRNG."""
        self._autoready()
        out = PyBytes_FromStringAndSize(NULL, length)
        cdef unsigned long len_read = self.desc.read(out, length, &self.state)
        return out[:len_read]
    
    def get_state(self):
        """Get the internal entropy pool, restored with PRNG.set_state(...).

        Note that when restored, the PRNG will not read out the same bits as
        it would have before. It only maintains the amount of entropy in the
        pool.

        Two PRNGs set to the same state should, however, produce the same data.
        
        >>> a = yarrow()
        >>> a.add_entropy(b'from a random oracle')
        >>> state = a.get_state()
        >>> b = yarrow()
        >>> b.set_state(state)
        >>> b.read(8)
        b'\\xa8\\xe6\\xbc\\xbf \\xb2\\x18!'

        """
        self._autoready()
        cdef unsigned long outlen = self.desc.export_size
        out = PyBytes_FromStringAndSize(NULL, outlen)
        check_for_error(self.desc.get_state(out, &outlen, &self.state))
        return out[:outlen]
    
    def set_state(self, bytes input):
        """Seed from an old entropy pool.

        See PRNG.get_state() for an example.

        """
        check_for_error(self.desc.set_state(input, len(input), &self.state))
        self.ready = False
    
    

names = ${repr(set(prng_names))}
% for name in prng_names:
def ${name}(*args, **kwargs): return PRNG(${repr(name)}, *args, **kwargs)
% endfor


cdef PRNG conform_prng(prng):
    """Turn a user supplied PRNG into an actual PRNG.

    If only a name or idx is supplied, it is autoseeded from the system rng.
    None defaults to the system rng (ie /dev/random).

    """
    if isinstance(prng, PRNG):
        return prng
    if prng is None or prng == 'sprng':
        return PRNG('sprng')
    return PRNG(prng, auto_seed=1024)

        

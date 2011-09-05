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
    if isinstance(input, basestring):
        idx = find_prng(input)
    elif isinstance(input, PRNG):
        idx = input.idx
    if idx < 0 or idx > max_prng_idx:
        raise Error('could not find prng %r' % input)
    return idx


def test_library():
    """Run internal libtomcrypt prng tests."""  
    % for name in prng_names:
    check_for_error(${name}_desc.test())
    % endfor




cdef class PRNG(object):
    
    def __init__(self, prng, entropy=None):
        self.idx = get_prng_idx(prng)
        self.desc = &prng_descriptors[self.idx]
        check_for_error(self.desc.start(&self.state))
        self.ready = False
        if isinstance(entropy, int):
            self.auto_seed(entropy)
        elif isinstance(entropy, str):
            self.add_entropy(entropy)
        elif entropy is not None:
            raise TypeError('entropy must be int or str; got %r' % entropy)
    
    def __dealloc__(self):
        self.desc.done(&self.state)
    
    def auto_seed(self, length):
        entropy = PyString_FromStringAndSize(NULL, length)
        read_len = rng_get_bytes(entropy, length, NULL)
        if read_len != length:
            raise Error('only read %d of requested %d' % (read_len, length))
        self.add_entropy(entropy)
        
    def add_entropy(self, input):
        check_for_error(self.desc.add_entropy(input, len(input), &self.state))
        self.ready = False
    
    def read(self, int length):
        if not self.ready:
            check_for_error(self.desc.ready(&self.state))
            self.ready = True
        out = PyString_FromStringAndSize(NULL, length)
        cdef unsigned long len_read = self.desc.read(out, length, &self.state)
        return out[:len_read]
    
    def get_state(self):
        raise NotImplementedError()
    
    def set_state(self, input):
        raise NotImplementedError()
    
    

names = ${repr(set(prng_names))}
% for name in prng_names:
def ${name}(*args, **kwargs): return PRNG(${repr(name)}, *args, **kwargs)
% endfor

        

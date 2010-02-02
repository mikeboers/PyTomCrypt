<%!

key_parts = 'e d N p q qP dP dQ'.split()

%>

cdef class Key


RSA_PRIVATE = PK_PRIVATE
RSA_PUBLIC  = PK_PUBLIC

cdef class Key(object):

    cdef rsa_key key
    
    def __dealloc__(self):
        rsa_free(&self.key)
    
    @classmethod
    def generate(cls, *args, **kwargs):
        return generate_key(cls, *args, **kwargs)
    
    def to_string(self, int type=PK_PRIVATE):
        out = PyString_FromStringAndSize(NULL, 4096)
        cdef unsigned long length = 4096
        check_for_error(rsa_export(out, &length, type, &self.key))
        return out[:length]
    
    @classmethod
    def from_string(cls, *args, **kwargs):
        return key_from_string(cls, *args, **kwargs)
        
    def as_dict(self, int radix=16):
        cdef char buf[1024]
        out = {}
        % for x in key_parts:
        check_for_error(mp.write_radix(self.key.${x}, buf, radix))
        out[${repr(x)}] = buf
        % endfor
        return out
    
    @property
    def size(self):
        return mp.count_bits(self.key.N)
    
    def dump(self):
        cdef char buf[1024]

        mp.write_radix(self.key.e, buf, 16)
        print 'e', buf
        mp.write_radix(self.key.p, buf, 16)
        print 'p', buf
        mp.write_radix(self.key.q, buf, 16)
        print 'q', buf
        mp.write_radix(self.key.N, buf, 16)
        print 'N', buf
        

cpdef Key generate_key(cls, int size=2048, long e=65537, PRNG prng=None):
    if prng is None:
        prng = PRNG('sprng')
    cdef Key key = cls()
    check_for_error(rsa_make_key(&prng.state, prng.idx, size / 8, e, &key.key))
    return key


cpdef Key key_from_string(cls, str input):
    cdef Key key = cls()
    check_for_error(rsa_import(input, len(input), &key.key))
    return key



        
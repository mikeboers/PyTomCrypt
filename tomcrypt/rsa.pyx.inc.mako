<%!

key_parts = 'e d N p q qP dP dQ'.split()

%>

cdef class Key




cdef class Key(object):

    cdef rsa_key key
    
    def __dealloc__(self):
        rsa_free(&self.key)
    
    @classmethod
    def generate(cls, *args, **kwargs):
        return generate_key(cls, *args, **kwargs)
    
    def as_dict(self, int radix=16):
        cdef char buf[1024]
        out = {}
        % for x in key_parts:
        check_for_error(mp.write_radix(self.key.${x}, buf, radix))
        out[${repr(x)}] = buf
        % endfor
        return out
    
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
        
        print 'size', mp.count_bits(self.key.N)
        print 'lsb size', mp.count_lsb_bits(self.key.N)
        
        % for x in key_parts:
        print sizeof(self.key.${x}),
        % endfor
        print
        
    

cpdef Key generate_key(cls, int size=2048/8, long e=65537, PRNG prng=None):
    if prng is None:
        prng = PRNG('sprng')
    cdef Key key = cls()
    check_for_error(rsa_make_key(&prng.state, prng.idx, size, e, &key.key))
    return key



        
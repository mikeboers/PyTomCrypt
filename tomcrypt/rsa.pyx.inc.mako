<%!

key_parts = 'e d N p q qP dP dQ'.split()

%>

RSA_TYPE_PRIVATE = _RSA_TYPE_PRIVATE
RSA_TYPE_PUBLIC  = _RSA_TYPE_PUBLIC

_rsa_type_map = {
    RSA_TYPE_PRIVATE: RSA_TYPE_PRIVATE,
    RSA_TYPE_PUBLIC : RSA_TYPE_PUBLIC,
    'private': RSA_TYPE_PRIVATE,
    'public' : RSA_TYPE_PUBLIC
}

RSA_PAD_V1_5 = _RSA_PAD_V1_5
RSA_PAD_OAEP = _RSA_PAD_OAEP
RSA_PAD_PSS  = _RSA_PAD_PSS


cdef object key_sentinel = object()

cdef class RSAKey(object):

    cdef rsa_key key
    
    def __init__(self, x=None):
        if x is not key_sentinel:
            raise ValueError('cannot make new keys yourself')
        
    def __dealloc__(self):
        rsa_free(&self.key)
    
    @classmethod
    def generate(cls, *args, **kwargs):
        return generate_rsa_key(cls, *args, **kwargs)
    
    def as_string(self, type=RSA_TYPE_PRIVATE):
        out = PyString_FromStringAndSize(NULL, 4096)
        cdef unsigned long length = 4096
        if type not in _rsa_type_map:
            raise ValueError('dont understand key type %r' % type)
        check_for_error(rsa_export(out, &length, _rsa_type_map[type], &self.key))
        return out[:length]
    
    @classmethod
    def from_string(cls, *args, **kwargs):
        return rsa_key_from_string(cls, *args, **kwargs)
        
    def as_dict(self, int radix=16, bool full=False):
        cdef char buf[1024]
        out = {}
        % for x in 'N p q'.split():
        check_for_error(mp.write_radix(self.key.${x}, buf, radix))
        out[${repr(x)}] = buf
        % endfor
        if full:
            % for x in set(key_parts) - set('Npq'):
            check_for_error(mp.write_radix(self.key.${x}, buf, radix))
            out[${repr(x)}] = buf
            % endfor
        return out
    
    @property
    def size(self):
        return mp.count_bits(self.key.N)
    


cdef RSAKey new_rsa_key(cls=RSAKey):
    return cls(key_sentinel)

cpdef RSAKey generate_rsa_key(cls, int size=2048, long e=65537, PRNG prng=None):
    if prng is None:
        prng = PRNG('sprng')
    cdef RSAKey key = new_rsa_key(cls)
    check_for_error(rsa_make_key(&prng.state, prng.idx, size / 8, e, &key.key))
    return key


cpdef RSAKey rsa_key_from_string(cls, str input):
    cdef RSAKey key = new_rsa_key(cls)
    check_for_error(rsa_import(input, len(input), &key.key))
    return key



        
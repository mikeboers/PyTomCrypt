<%!

key_parts = 'e d N p q qP dP dQ'.split()

%>

import re
import base64


RSA_TYPE_PRIVATE = _RSA_TYPE_PRIVATE
RSA_TYPE_PUBLIC  = _RSA_TYPE_PUBLIC

_rsa_type_map = {
    RSA_TYPE_PRIVATE: RSA_TYPE_PRIVATE,
    RSA_TYPE_PUBLIC : RSA_TYPE_PUBLIC,
    'private': RSA_TYPE_PRIVATE,
    'public' : RSA_TYPE_PUBLIC
}


RSA_PAD_NONE = 0
RSA_PAD_V1_5 = _RSA_PAD_V1_5
RSA_PAD_OAEP = _RSA_PAD_OAEP
RSA_PAD_PSS  = _RSA_PAD_PSS

for i in range(4):
    if i not in (RSA_PAD_V1_5, RSA_PAD_OAEP, RSA_PAD_PSS):
        RSA_PAD_NONE = i
        break

_rsa_pad_map = {
    RSA_PAD_NONE: RSA_PAD_NONE,
    RSA_PAD_V1_5: RSA_PAD_V1_5,
    RSA_PAD_OAEP: RSA_PAD_OAEP,
    RSA_PAD_PSS : RSA_PAD_PSS,
    'none': RSA_PAD_NONE,
    'v1.5': RSA_PAD_V1_5,
    'oaep': RSA_PAD_OAEP,
    'pss' : RSA_PAD_PSS,
}


RSA_FORMAT_PEM = 'pem'
RSA_FORMAT_DER = 'der'


cdef object key_sentinel = object()


cdef class RSAKey(object):

    cdef rsa_key key
    cdef object _public
    cdef int _init_type
    
    def __init__(self, x=None):
        if x is not key_sentinel:
            raise ValueError('cannot manually init new %s' % self.__class__)
        self._public = False
        # To track if the key was inited at all.
        self._init_type = self.key.type
        
    def __dealloc__(self):
        # Only free the key if it was inited.
        if self._init_type != self.key.type:
            rsa_free(&self.key)
    
    @classmethod
    def generate(cls, *args, **kwargs):
        return generate_rsa_key(cls, *args, **kwargs)
    
    def as_string(self, type=None, format=RSA_FORMAT_PEM):
        
        if type is None:
            type = self.key.type
        if type not in _rsa_type_map:
            raise ValueError('unknown key type %r' % type)
        type = _rsa_type_map[type]
        if self.key.type == _RSA_TYPE_PUBLIC and type == RSA_TYPE_PRIVATE:
            raise ValueError('cant get private key from public key')
        
        out = PyString_FromStringAndSize(NULL, 4096)
        cdef unsigned long length = 4096
        check_for_error(rsa_export(out, &length, _rsa_type_map[type], &self.key))
        
        if format == RSA_FORMAT_DER:
            return out[:length]
        else:
            return '-----BEGIN %(type)s KEY-----\n%(key)s-----END %(type)s KEY-----\n' % {
                'key': out[:length].encode('base64'),
                'type': 'RSA PRIVATE' if type == RSA_TYPE_PRIVATE else 'PUBLIC'
            }
    
    @classmethod
    def from_string(cls, *args, **kwargs):
        return rsa_key_from_string(cls, *args, **kwargs)
        
    def as_dict(self, int radix=16, bool full=False):
        cdef char buf[1024]
        out = {}
        % for x in 'Ned':
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
    def is_private(self):
        return self.key.type == _RSA_TYPE_PRIVATE
    
    @property
    def is_public(self):
        return self.key.type == _RSA_TYPE_PUBLIC
    
    @property
    def size(self):
        return mp.count_bits(self.key.N)
    
    @property
    def type(self):
        return self.key.type
    
    cdef RSAKey copy(self):
        cdef RSAKey copy = new_rsa_key(self.__class__)
        copy.key.type = self.key.type
        
        % for x in key_parts:
        check_for_error(mp.init_copy(&copy.key.${x}, self.key.${x}))
        % endfor
        
        return copy
    
    cdef RSAKey copy_public(self):
        cdef RSAKey copy = new_rsa_key(self.__class__)
        copy.key.type = _RSA_TYPE_PUBLIC
        
        % for x in 'Ne':
        check_for_error(mp.init_copy(&copy.key.${x}, self.key.${x}))
        % endfor
        
        # Just need to initialize these parts, which sets them to zero.
        % for x in set(key_parts) - set('Ne'):
        check_for_error(mp.init(&copy.key.${x}))
        ## check_for_error(mp.set_int(copy.key.${x}, 0))
        % endfor
        
        return copy
    
    @property
    def public(self):
        if self._public is False:
            if self.is_public:
                self._public = None
            self._public = self.copy_public()
        return self._public
    
    cpdef encrypt(self, str input, PRNG prng=None, HashDescriptor hash=None, padding=RSA_PAD_OAEP):
        if padding not in _rsa_pad_map:
            raise ValueError('unknown rsa padding %r' % padding)
        padding = _rsa_pad_map[padding]
        if prng is None:
            prng = PRNG('sprng')
        if hash is None:
            hash = HashDescriptor('sha1')
        
        out = PyString_FromStringAndSize(NULL, 4096)
        cdef unsigned long out_length = 4096
        
        if padding == RSA_PAD_NONE:
            check_for_error(rsa_exptmod(
                input, len(input),
                out, &out_length,
                RSA_TYPE_PUBLIC, # For encryption
                &self.key))
        else:
            check_for_error(rsa_encrypt_key_ex(
                input, len(input),
                out, &out_length,
                NULL, 0,
                &prng.state, prng.idx,
                hash.idx,
                padding,
                &self.key
            ))
        
        return out[:out_length]
    
    cpdef decrypt(self, str input, HashDescriptor hash=None, padding=RSA_PAD_OAEP):
        if padding not in _rsa_pad_map:
            raise ValueError('unknown rsa padding %r' % padding)
        padding = _rsa_pad_map[padding]
        if hash is None:
            hash = HashDescriptor('sha1')

        out = PyString_FromStringAndSize(NULL, 4096)
        cdef unsigned long out_length = 4096
        cdef int status = 0
        
        if padding == RSA_PAD_NONE:
            check_for_error(rsa_exptmod(
                input, len(input),
                out, &out_length,
                RSA_TYPE_PRIVATE, # For encryption
                &self.key))
        else:
            check_for_error(rsa_decrypt_key_ex(
                input, len(input),
                out, &out_length,
                NULL, 0,
                hash.idx,
                padding,
                &status,
                &self.key
            ))        
            if not status:
                raise Error('invalid padding')
        
        return out[:out_length]


cdef RSAKey new_rsa_key(cls=RSAKey):
    return cls(key_sentinel)


cpdef RSAKey generate_rsa_key(cls, int size=1024, long e=65537, PRNG prng=None):
    if prng is None:
        prng = PRNG('sprng')
    cdef RSAKey key = new_rsa_key(cls)
    check_for_error(rsa_make_key(&prng.state, prng.idx, size / 8, e, &key.key))
    return key


_rsa_pem_re = re.compile(r'^\s*-----BEGIN ((?:RSA )?(?:PRIVATE|PUBLIC)) KEY-----(.+)-----END \1 KEY-----', re.DOTALL)


cpdef RSAKey rsa_key_from_string(cls, input):
    cdef RSAKey key = new_rsa_key(cls)
    m = _rsa_pem_re.match(input)
    if m:
        input = m.group(2).decode('base64')
    check_for_error(rsa_import(input, len(input), &key.key))
    return key



        
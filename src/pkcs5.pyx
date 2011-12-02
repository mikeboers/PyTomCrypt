from tomcrypt._core cimport *
from tomcrypt.hash cimport Descriptor as HashDescriptor, conform_hash
from tomcrypt import Error


cpdef bytes pkcs5_alg1(bytes password, bytes salt, int iteration_count, hash):
    if len(salt) != 8:
        raise Error('salt must be length 8')
    cdef HashDescriptor desc = conform_hash(hash)
    cdef unsigned long outlen = desc.digest_size
    out = PyBytes_FromStringAndSize(NULL, outlen)
    c_pkcs5_alg1(password, len(password), salt, iteration_count, desc.idx, out, &outlen)
    return out[:outlen]


cpdef bytes pkcs5_alg2(bytes password, bytes salt, int iteration_count, hash):  
    cdef HashDescriptor desc = conform_hash(hash)
    cdef unsigned long outlen = desc.digest_size
    out = PyBytes_FromStringAndSize(NULL, outlen)
    c_pkcs5_alg2(password, len(password), salt, len(salt), iteration_count, desc.idx, out, &outlen)
    return out[:outlen]


pkcs5 = pkcs5_alg2




from tomcrypt._core cimport *
from tomcrypt.prng cimport PRNG, conform_prng
from tomcrypt import Error

cpdef pkcs1_v1_5_encode(bytes message, block_type, int modulus_bitlen, prng=None):

    if block_type in (LTC_PKCS_1_EME, 'eme', 'encrypt', 'decrypt'):
        block_type = LTC_PKCS_1_EME
    elif block_type in (LTC_PKCS_1_EMSA, 'emsa', 'sign', 'verify'):
        block_type = LTC_PKCS_1_EMSA
    else:
        raise Error('unknown block_type %r' % block_type)
    
    cdef PRNG c_prng = conform_prng(prng)
    
    cdef unsigned long outlen = modulus_bitlen / 8 + 1
    out = PyBytes_FromStringAndSize(NULL, outlen)
    check_for_error(c_pkcs1_v1_5_encode(
        message, len(message),
        block_type,
        modulus_bitlen,
        &c_prng.state,
        c_prng.idx,
        out,
        &outlen
    ))
    
    return out[:outlen]

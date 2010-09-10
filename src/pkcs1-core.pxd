cdef extern from "tomcrypt.h" nogil:
    
    int LTC_PKCS_1_EME "LTC_LTC_PKCS_1_EME"
    int LTC_PKCS_1_EMSA "LTC_LTC_PKCS_1_EMSA"
    
    int c_pkcs1_v1_5_encode "pkcs_1_v1_5_encode" (
        unsigned char *msg,
        unsigned long msglen,
        int block_type,
        unsigned long modulus_bitlen,
        prng_state *prng,
        int prng_idx,
        unsigned char *out,
        unsigned long *outlen
    )
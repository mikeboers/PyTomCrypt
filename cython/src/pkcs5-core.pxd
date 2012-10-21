cdef extern from "tomcrypt.h" nogil:
    
    int c_pkcs5_alg1 "pkcs_5_alg1"(
        unsigned char *password,
        unsigned long password_len,
        unsigned char *salt,
        int iteration_count,
        int hash_idx,
        unsigned char *out,
        unsigned long *outlen)
        
    int c_pkcs5_alg2 "pkcs_5_alg2"(
        unsigned char *password,
        unsigned long password_len,
        unsigned char *salt,
        unsigned long salt_len,
        int iteration_count,
        int hash_idx,
        unsigned char *out,
        unsigned long *outlen)
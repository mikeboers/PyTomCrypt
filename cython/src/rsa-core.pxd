
cdef extern from "tomcrypt.h" nogil:

    cdef int c_RSA_TYPE_PUBLIC  "PK_PUBLIC"
    cdef int c_RSA_TYPE_PRIVATE "PK_PRIVATE"
    
    ctypedef struct rsa_key:
        int type # One of PK_PUBLIC or PK_PRIVATE
        
        # The public exponent 
        void *e
        # The private exponent 
        void *d
        # The modulus 
        void *N
        # The p factor of N 
        void *p
        # The q factor of N 
        void *q
        # The 1/q mod p CRT param 
        void *qP
        # The d mod (p - 1) CRT param 
        void *dP
        # The d mod (q - 1) CRT param 
        void *dQ
    
    int rsa_make_key(prng_state *state, int prng_idx, int size, long e, rsa_key *key)
    void rsa_free(rsa_key *key)
    
    int rsa_import(unsigned char *input, unsigned long inlen, rsa_key *key)
    int rsa_export(unsigned char *out, unsigned long *outlen, int type, rsa_key *key)
    
    
    cdef int c_RSA_PAD_V1_5 "LTC_LTC_PKCS_1_V1_5"
    cdef int c_RSA_PAD_OAEP "LTC_LTC_PKCS_1_OAEP"
    cdef int c_RSA_PAD_PSS  "LTC_LTC_PKCS_1_PSS"
    
    int rsa_exptmod(
        unsigned char *input, unsigned long inlen,
        unsigned char *out  , unsigned long *outlen,
        int mode,
        rsa_key *key)
    
    int rsa_encrypt_key_ex(
        unsigned char *input, unsigned long inlen,
        unsigned char *out, unsigned long *outlen,
        unsigned char *lparam, unsigned long lparamlen,
        prng_state *prng, int prng_idx,
        int hash_idx,
        int padding,
        rsa_key *key)
    
    int rsa_decrypt_key_ex(
        unsigned char *input, unsigned long inlen,
        unsigned char *out, unsigned long *outlen,
        unsigned char *lparam, unsigned long lparamlen,
        int hash_idx,
        int padding,
        int *success,
        rsa_key *key)
    
    int rsa_sign_hash_ex(
        unsigned char *input, unsigned long inlen,
        unsigned char *out, unsigned long *outlen,
        int padding,
        prng_state *prng, int prng_idx,
        int hash_idx,
        unsigned long saltlen,
        rsa_key *key)
        
    int rsa_verify_hash_ex(
        unsigned char *sig,  unsigned long siglen,
        unsigned char *hash, unsigned long hashlen,
        int padding,
        int hash_idx,
        unsigned long saltlen,
        int *success,
        rsa_key *key)
    


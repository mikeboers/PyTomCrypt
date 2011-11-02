cdef extern from "tomcrypt.h" nogil:
    
    
    ctypedef struct ecc_curve "ltc_ecc_set_type":
        
        int size
        char *name

        # Everything below is a string of hex. See LibTomCrypt's PK headers
        # for more information.
        char *prime
        char *B
        char *order
        char *Gx
        char *Gy

    # The list of NIST recommended curves that are packaged with LibTomCrypt.
    ecc_curve ecc_nist_curves "ltc_ecc_sets" []

    ctypedef struct ecc_point:
        void *x
        void *y
        void *z

    int PK_PRIVATE
    int PK_PUBLIC

    ctypedef struct ecc_key:
        int type
        int idx

        # The next 3 are renamed so the code looks more sensical. I may
        # change back to the original names in the future.
        ecc_curve *curve "dp"
        ecc_point public "pubkey"
        void *private "k"

    # LTC functions for allocating/generating/deallocating keys.
    int ecc_make_key(prng_state *prng, int wprng, int keysize, ecc_key *key)
    int ecc_make_key_ex(prng_state *prng, int wprng, ecc_key *key, ecc_curve *dp)
    void ecc_free(ecc_key *key)

    # LTC functions for import/export into LTC format.
    int ecc_export(unsigned char *out, unsigned long *outlen, int type, ecc_key *key)
    int ecc_import(unsigned char *input, unsigned long inlen, ecc_key *key)
    int ecc_import_ex(unsigned char *input, unsigned long inlen, ecc_key *key, ecc_curve *dp)
    # LTC functions for import/export into standard format (only public keys).
    int ecc_ansi_x963_export(ecc_key *key, unsigned char *out, unsigned long *outlen)
    int ecc_ansi_x963_import(unsigned char *input, unsigned long inlen, ecc_key *key)
    int ecc_ansi_x963_import_ex(unsigned char *input, unsigned long inlen, ecc_key *key, ecc_curve *dp)
    
    # LTC functions for high-level ECC operations.

    int ecc_shared_secret(
        ecc_key *private_key,
        ecc_key *public_key,
        unsigned char *out,
        unsigned long *outlen
    )
    
    int ecc_encrypt_key(
        unsigned char *input, unsigned long inlen,
        unsigned char *out, unsigned long *outlen,
        prng_state *prng, int wprng,
        int hash,
        ecc_key *key
    )

    int ecc_decrypt_key(
        unsigned char *input, unsigned long inlen,
        unsigned char *out, unsigned long *outlen,
        ecc_key *key
    )

    int ecc_sign_hash(
        unsigned char *input, unsigned long inlen,
        unsigned char *out, unsigned long *outlen,
        prng_state *prng, int wprng,
        ecc_key *key
    )

    int ecc_verify_hash(
        unsigned char *sig, unsigned long siglen,
        unsigned char *hash, unsigned long hashlen,
        int *stat,
        ecc_key *key
    )



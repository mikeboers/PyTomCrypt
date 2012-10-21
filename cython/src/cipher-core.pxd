cdef extern from "tomcrypt.h" nogil:

    int CTR_COUNTER_BIG_ENDIAN
    
    # Symmetric state for all the cipher modes.
    % for name in cipher_no_auth_modes:
    ctypedef struct symmetric_${name} "symmetric_${name.upper()}":
        pass
    % endfor
    % for name in cipher_auth_modes:
    ctypedef struct ${name}_state:
        pass
    % endfor
    
    # Pull in all the cipher functions for all the modes.

    int ecb_start(int cipher, unsigned char *key, int keylen, int num_rounds, symmetric_ecb *ecb)
    int ctr_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, int ctr_mode, symmetric_ctr *ctr)
    % for name in cipher_simple_modes:
    int ${name}_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, symmetric_${name} *${name})
    % endfor
    int lrw_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, unsigned char *tweak, int num_rounds, symmetric_lrw *lrw)
    int f8_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, unsigned char *salt_key, int skeylen, int num_rounds, symmetric_f8 *f8)
    % for name in cipher_no_auth_modes:
    int ${name}_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_${name} *${name})
    int ${name}_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_${name} *${name})
    int ${name}_done(void *${name})
    % endfor
    % for name in cipher_iv_modes:
    int ${name}_getiv(unsigned char *iv, unsigned long *len, symmetric_${name} *${name})
    int ${name}_setiv(unsigned char *iv, unsigned long len, symmetric_${name} *${name})
    % endfor
    
    # EAX functions.
    int eax_init(
        eax_state *eax,
        int cipher,
        unsigned char *key, unsigned long keylen,
        unsigned char *nonce, unsigned long noncelen,
        unsigned char *header, unsigned long headerlen
    )
    int eax_addheader(eax_state *eax, unsigned char *header, unsigned long length)
    int eax_encrypt(eax_state *eax, unsigned char *pt, unsigned char *ct, unsigned long length)
    int eax_decrypt(eax_state *eax, unsigned char *ct, unsigned char *pt, unsigned long length)
    int eax_done(eax_state *eax, unsigned char *tag, unsigned long *taglen)
    int eax_test()

    # OBC functions.
    # int ocb_init(
    #     ocb_state *eax,
    #     int cipher,
    #     unsigned char *key, unsigned long keylen,
    #     unsigned char *nonce
    # )
    # int ocb_encrypt(ocb_state *eax, unsigned char *pt, unsigned char *ct, unsigned long length)
    # int ocb_decrypt(ocb_state *eax, unsigned char *ct, unsigned char *pt, unsigned long length)
    # int ocb_done_encrypt(
    #     ocb_state *ocb,
    #     unsigned char *pt, unsigned long ptlen,
    #     unsigned char *ct,
    #     unsigned char *tag, unsigned long *taglen
    # )
    # int ocb_done_decrypt(
    #     ocb_state *ocb,
    #     unsigned char *ct, unsigned long ctlen,
    #     unsigned char *pt,
    #     unsigned char *tag, unsigned long taglen,
    #     int *res
    # )
    



    
    # Cipher descriptor.
    cdef struct cipher_desc "ltc_cipher_descriptor":
        char * name
        int min_key_size "min_key_length"
        int max_key_size "max_key_length"
        int block_size "block_length"
        int default_rounds
        int key_size "keysize" (int *key_size)
        
        # There are a bunch of encrypt/decrypt functions here as well that we
        # really don't care about.
    
    # The array which contains the descriptors once setup.
    cipher_desc cipher_descriptors "cipher_descriptor" []
    
    # The descriptors themselves.
    % for name in cipher_names:
    cipher_desc ${name}_desc
    % if not name.endswith('_enc'):
    int ${name}_test()
    % endif
    % endfor
        
    # Functions for registering and finding the registered ciphers.
    int register_cipher(cipher_desc *cipher)
    int find_cipher(char * name)

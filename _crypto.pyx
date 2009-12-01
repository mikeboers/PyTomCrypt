
cdef extern from "tomcrypt.h":
    int c_CRYPT_OK "CRYPT_OK"
    ctypedef struct c_symmetric_key "symmetric_key":
        pass
    int c_aes_setup "aes_setup" (unsigned char *key, int keylen, int rounds, c_symmetric_key *skey)
    int c_aes_ecb_encrypt "aes_ecb_encrypt" (char *pt, char *ct, c_symmetric_key *skey)
    int c_aes_ecb_decrypt "aes_ecb_encrypt" (char *ct, char *pt, c_symmetric_key *skey)
    char * c_error_to_string "error_to_string" (int err)

CRYPT_OK = c_CRYPT_OK

def error_to_string(err):
    return c_error_to_string(err)

class CryptoError(Exception):
    
    def __init__(self, err):
        Exception.__init__(self, c_error_to_string(err), err)

cdef class AES(object):
    
    cdef c_symmetric_key skey
    cdef object key
    
    def __init__(self, key):

        self.key = str(key)
        keylen = len(key)
    
        ret = c_aes_setup(self.key, keylen, 0, &self.skey)
        if ret != CRYPT_OK:
            raise CryptoError(ret)
    
    def encrypt(self, plaintext):
        cdef char ciphertext[16]
        c_aes_ecb_encrypt(plaintext, ciphertext, &self.skey)
        return ciphertext
    
    def decrypt(self, ciphertext):
        cdef char plaintext[16]
        c_aes_ecb_encrypt(ciphertext, plaintext, &self.skey)
        return plaintext      
        
    
            
    


cdef extern from "tomcrypt.h":

    int CRYPT_OK
    char * error_to_string(int err)
    
    # Generic symmetric key, and for all of the supported modes.
    ctypedef struct symmetric_key:
        pass
    ctypedef struct symmetric_ECB:
        pass
    ctypedef struct symmetric_CBC:
        pass
    ctypedef struct symmetric_CTR:
        pass
    ctypedef struct symmetric_CFB:
        pass
    ctypedef struct symmetric_OFB:
        pass
    
    # Generic ECB encryption functions
    int ecb_start(int cipher, unsigned char *key, int keylen, int rounds, symmetric_ECB *ecb)
    int ecb_encrypt(unsigned char *pt, unsigned char *ct, long len, symmetric_ECB *ecb)
    int ecb_decrypt(unsigned char *ct, unsigned char *pt, long len, symmetric_ECB *ecb)
    int ecb_done(symmetric_ECB *ecb)
    
    # Cipher descriptor.
    cdef struct cipher_desc "ltc_cipher_descriptor":
        char * name
        int min_key_length
        int max_key_length
        int block_length
        int default_rounds
        int setup(char *key, int keylen, int rounds, symmetric_key *skey)
    
    # The array which contains the descriptors once setup.
    cipher_desc cipher_descriptors "cipher_descriptor" []
    
    # The descriptors themselves.
    cipher_desc aes_desc
    cipher_desc des_desc
    cipher_desc blowfish_desc
    
    # Functions for registering and finding the registered ciphers.
    int register_cipher(cipher_desc *cipher)
    int find_cipher(char * name)


register_cipher(&aes_desc)
register_cipher(&des_desc)

# ciphers_indices = {}
# 
# cdef int i = 0
# while True:
#     if not cipher_descriptors[i].name:
#         break
#     ciphers_indices[str(cipher_descriptors[i].name)] = i
#     i += 1
# print ciphers_indices

class CryptoError(Exception):
    
    def __init__(self, err):
        Exception.__init__(self, error_to_string(err), err)

cdef class Cipher(object):
    
    cdef int cipher_i
    cdef cipher_desc cipher
    cdef symmetric_ECB ecb
    
    def __init__(self, key, cipher='aes'):
        
        cdef int cipher_i
        
        self.cipher_i = find_cipher(cipher)
        if self.cipher_i < 0:
            raise ValueError('could not find %r' % cipher)
        self.cipher = cipher_descriptors[self.cipher_i]
        print 'name', self.cipher.name
        print 'min ', self.cipher.min_key_length
        print 'max ', self.cipher.max_key_length
        print 'blk ', self.cipher.block_length
        print 'rnds', self.cipher.default_rounds
        
        self.__start(key)
    
    def __start(self, key):
        res = ecb_start(self.cipher_i, key, len(key), 0, &self.ecb)
        if res != CRYPT_OK:
            raise CryptoError(res)
        
    def encrypt(self, plaintext):
        cdef unsigned char ciphertext[255]
        cdef int i
        cdef long length
        
        length = len(plaintext)
        
        res = ecb_encrypt(plaintext, ciphertext, length, &self.ecb)
        if res != CRYPT_OK:
            raise CryptoError(res)
        
        out = []
        for i in range(len(plaintext)):
            out.append(chr(ciphertext[i]))
        return ''.join(out)
        
    def decrypt(self, plaintext):
        cdef unsigned char ciphertext[255]
        cdef int i
        cdef long length

        length = len(plaintext)

        res = ecb_decrypt(plaintext, ciphertext, length, &self.ecb)
        if res != CRYPT_OK:
            raise CryptoError(res)

        out = []
        for i in range(len(plaintext)):
            out.append(chr(ciphertext[i]))

        return ''.join(out) 
        
    
            
    

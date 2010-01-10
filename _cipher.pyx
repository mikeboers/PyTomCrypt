





cdef extern from "tomcrypt.h":

	int CRYPT_OK
	char * error_to_string(int err)

	ctypedef struct symmetric_key:
		pass
	ctypedef struct symmetric_ecb "symmetric_ECB":
		pass
	ctypedef struct symmetric_cbc "symmetric_CBC":
		pass
	ctypedef struct symmetric_ctr "symmetric_CTR":
		pass
	ctypedef struct symmetric_cfb "symmetric_CFB":
		pass
	ctypedef struct symmetric_ofb "symmetric_OFB":
		pass

	int ecb_start(int cipher, unsigned char *key, int keylen, int num_rounds, symmetric_ecb *ecb)
	int ecb_encrypt(unsigned char *pt, unsigned char *ct, long len, symmetric_ecb *ecb)
	int ecb_decrypt(unsigned char *ct, unsigned char *pt, long len, symmetric_ecb *ecb)
	int xxx_done(symmetric_ecb *ecb)
	int ctr_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, int ctr_mode, symmetric_ctr *ctr)
	int ctr_encrypt(unsigned char *pt, unsigned char *ct, long len, symmetric_ctr *ctr)
	int ctr_decrypt(unsigned char *ct, unsigned char *pt, long len, symmetric_ctr *ctr)
	int xxx_done(symmetric_ctr *ctr)
	int cbc_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, symmetric_cbc *cbc)
	int cbc_encrypt(unsigned char *pt, unsigned char *ct, long len, symmetric_cbc *cbc)
	int cbc_decrypt(unsigned char *ct, unsigned char *pt, long len, symmetric_cbc *cbc)
	int xxx_done(symmetric_cbc *cbc)
	int cfb_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, symmetric_cfb *cfb)
	int cfb_encrypt(unsigned char *pt, unsigned char *ct, long len, symmetric_cfb *cfb)
	int cfb_decrypt(unsigned char *ct, unsigned char *pt, long len, symmetric_cfb *cfb)
	int xxx_done(symmetric_cfb *cfb)
	int ofb_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, symmetric_ofb *ofb)
	int ofb_encrypt(unsigned char *pt, unsigned char *ct, long len, symmetric_ofb *ofb)
	int ofb_decrypt(unsigned char *ct, unsigned char *pt, long len, symmetric_ofb *ofb)
	int xxx_done(symmetric_ofb *ofb)

	cdef struct cipher_desc "ltc_cipher_descriptor":
		char * name
		int min_key_length
		int max_key_length
		int block_length
		int default_rounds
		int setup(char *key, int keylen, int rounds, symmetric_key *skey)

	cipher_desc cipher_descriptors "cipher_descriptor" []

	cipher_desc aes_desc
	cipher_desc des_desc
	cipher_desc blowfish_desc
	cipher_desc rijndael_desc

	int register_cipher(cipher_desc *cipher)
	int find_cipher(char * name)


register_cipher(&aes_desc)
register_cipher(&des_desc)
register_cipher(&blowfish_desc)
register_cipher(&rijndael_desc)


class CryptoError(Exception):

	def __init__(self, err):
		Exception.__init__(self, error_to_string(err), err)

cdef class Cipher(object):

	cdef int cipher_i
	cdef cipher_desc cipher
	cdef symmetric_ecb ecb

	def __init__(self, key, cipher='aes'):
		cdef int res

		self.cipher_i = find_cipher(cipher)
		if self.cipher_i < 0:
			raise ValueError('could not find %r' % cipher)
		self.cipher = cipher_descriptors[self.cipher_i]
		res = ecb_start(self.cipher_i, key, len(key), 0, &self.ecb)
		if res != CRYPT_OK:
			raise CryptoError(res)

	@property
	def name(self):
		return self.cipher.name

	@property
	def min_key_length(self):
		return self.cipher.min_key_length

	@property
	def max_key_length(self):
		return self.cipher.max_key_length

	@property
	def block_length(self):
		return self.cipher.block_length

	@property
	def default_rounds(self):
		return self.cipher.default_rounds

	def ecb_encrypt(self, plaintext):
		cdef int res
		ciphertext = '\0' * len(plaintext)
		res = ecb_encrypt(plaintext, ciphertext, len(plaintext), &self.ecb)
		if res != CRYPT_OK:
			raise CryptoError(res)
		return ciphertext

	def ecb_decrypt(self, ciphertext):
		cdef int res
		plaintext = '\0' * len(ciphertext)
		res = ecb_decrypt(ciphertext, plaintext, len(ciphertext), &self.ecb)
		if res != CRYPT_OK:
			raise CryptoError(res)
		return plaintext




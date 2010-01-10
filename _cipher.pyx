


modes = ['ecb', 'cbc', 'ctr', 'cfb', 'ofb']
simple_modes = ['cbc', 'cfb', 'ofb']
ciphers = ['aes', 'rijndael', 'des', 'blowfish']

cdef extern from "Python.h":

	object PyString_FromStringAndSize(char *s, Py_ssize_t len)

cdef extern from "tomcrypt.h":

	int CRYPT_OK
	int CTR_COUNTER_BIG_ENDIAN
	char * error_to_string(int err)
	
	# Generic symmetric key, and for all of the supported modes.
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
	
	# Pull in all the cipher functions for all the modes.
	int ecb_start(int cipher, unsigned char *key, int keylen, int num_rounds, symmetric_ecb *ecb)
	int ctr_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, int ctr_mode, symmetric_ctr *ctr)
	int cbc_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, symmetric_cbc *cbc)
	int cfb_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, symmetric_cfb *cfb)
	int ofb_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, symmetric_ofb *ofb)
	int ecb_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_ecb *ecb)
	int ecb_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_ecb *ecb)
	int ecb_done(symmetric_ecb *ecb)
	int cbc_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_cbc *cbc)
	int cbc_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_cbc *cbc)
	int cbc_done(symmetric_cbc *cbc)
	int ctr_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_ctr *ctr)
	int ctr_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_ctr *ctr)
	int ctr_done(symmetric_ctr *ctr)
	int cfb_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_cfb *cfb)
	int cfb_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_cfb *cfb)
	int cfb_done(symmetric_cfb *cfb)
	int ofb_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_ofb *ofb)
	int ofb_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_ofb *ofb)
	int ofb_done(symmetric_ofb *ofb)
	int ctr_getiv(unsigned char *iv, unsigned long *len, symmetric_ctr *ctr)
	int ctr_setiv(unsigned char *iv, unsigned long len, symmetric_ctr *ctr)
	int cbc_getiv(unsigned char *iv, unsigned long *len, symmetric_cbc *cbc)
	int cbc_setiv(unsigned char *iv, unsigned long len, symmetric_cbc *cbc)
	int cfb_getiv(unsigned char *iv, unsigned long *len, symmetric_cfb *cfb)
	int cfb_setiv(unsigned char *iv, unsigned long len, symmetric_cfb *cfb)
	int ofb_getiv(unsigned char *iv, unsigned long *len, symmetric_ofb *ofb)
	int ofb_setiv(unsigned char *iv, unsigned long len, symmetric_ofb *ofb)
	
	# Cipher descriptor.
	cdef struct cipher_desc "ltc_cipher_descriptor":
		char * name
		int min_key_length
		int max_key_length
		int block_length
		int default_rounds
		# int setup(char *key, int keylen, int rounds, symmetric_key *skey)
	
	# The array which contains the descriptors once setup.
	cipher_desc cipher_descriptors "cipher_descriptor" []
	
	# The descriptors themselves.
	cipher_desc aes_desc
	cipher_desc rijndael_desc
	cipher_desc des_desc
	cipher_desc blowfish_desc
		
	# Functions for registering and finding the registered ciphers.
	int register_cipher(cipher_desc *cipher)
	int find_cipher(char * name)


# Register all of the ciphers.
register_cipher(&aes_desc)
register_cipher(&rijndael_desc)
register_cipher(&des_desc)
register_cipher(&blowfish_desc)


class CryptoError(Exception):
	
	def __init__(self, err):
		Exception.__init__(self, error_to_string(err), err)

cdef class Cipher(object):
	
	cdef int cipher_i
	cdef cipher_desc cipher
	
	cdef symmetric_ecb ecb
	cdef symmetric_cbc cbc
	cdef symmetric_ctr ctr
	cdef symmetric_cfb cfb
	cdef symmetric_ofb ofb
	
	def __init__(self, key, iv='', cipher='aes', mode='cbc'):
		cdef int res
		
		self.cipher_i = find_cipher(cipher)
		if self.cipher_i < 0:
			raise ValueError('could not find %r' % cipher)
		self.cipher = cipher_descriptors[self.cipher_i]
		self.start(key, iv)
		
	cpdef start(self, key, iv=''):
		# Both the key and the iv are "const" for the start functions, so we
		# don't need to worry about making unique ones.
		iv = iv + ('\0' * self.cipher.block_length)
		res = ecb_start(self.cipher_i, key, len(key), 0, &self.ecb)
		if res != CRYPT_OK:
			raise CryptoError(res)
		res = ctr_start(self.cipher_i, iv, key, len(key), 0, CTR_COUNTER_BIG_ENDIAN, &self.ctr)
		if res != CRYPT_OK:
			raise CryptoError(res)
		res = cbc_start(self.cipher_i, iv, key, len(key), 0, &self.cbc)
		if res != CRYPT_OK:
			raise CryptoError(res)
		res = cfb_start(self.cipher_i, iv, key, len(key), 0, &self.cfb)
		if res != CRYPT_OK:
			raise CryptoError(res)
		res = ofb_start(self.cipher_i, iv, key, len(key), 0, &self.ofb)
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
	
	# ===== IV / ENCRYPTION / DECRYPTION FUNCTIONS =====
	
	
	cpdef ecb_encrypt(self, input):
		"""Encrypt a string in ECB mode."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = ecb_encrypt(<unsigned char *>input, <unsigned char*>output, length, &self.ecb)
		if res != CRYPT_OK:
			raise CryptoError(res)
		return output
	
	cpdef ecb_decrypt(self, input):
		"""Decrypt a string in ECB mode."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = ecb_decrypt(<unsigned char *>input, <unsigned char*>output, length, &self.ecb)
		if res != CRYPT_OK:
			raise CryptoError(res)
		return output
	
	cpdef ecb_done(self):
		cdef int res
		res = ecb_done(&self.ecb)
		if res != CRYPT_OK:
			raise CryptoError(res)
	cpdef cbc_get_iv(self):
		cdef int res
		cdef unsigned long length
		length = self.cipher.block_length
		iv = PyString_FromStringAndSize(NULL, length)
		res = cbc_getiv(<unsigned char *>iv, &length, &self.cbc)
		if res != CRYPT_OK:
			raise CryptoError(res)
		return iv
	
	cpdef cbc_set_iv(self, iv):
		cdef int res
		res = cbc_setiv(<unsigned char *>iv, len(iv), &self.cbc)
		if res != CRYPT_OK:
			raise CryptoError(res)
	
	cpdef cbc_encrypt(self, input):
		"""Encrypt a string in CBC mode."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = cbc_encrypt(<unsigned char *>input, <unsigned char*>output, length, &self.cbc)
		if res != CRYPT_OK:
			raise CryptoError(res)
		return output
	
	cpdef cbc_decrypt(self, input):
		"""Decrypt a string in CBC mode."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = cbc_decrypt(<unsigned char *>input, <unsigned char*>output, length, &self.cbc)
		if res != CRYPT_OK:
			raise CryptoError(res)
		return output
	
	cpdef cbc_done(self):
		cdef int res
		res = cbc_done(&self.cbc)
		if res != CRYPT_OK:
			raise CryptoError(res)
	cpdef ctr_get_iv(self):
		cdef int res
		cdef unsigned long length
		length = self.cipher.block_length
		iv = PyString_FromStringAndSize(NULL, length)
		res = ctr_getiv(<unsigned char *>iv, &length, &self.ctr)
		if res != CRYPT_OK:
			raise CryptoError(res)
		return iv
	
	cpdef ctr_set_iv(self, iv):
		cdef int res
		res = ctr_setiv(<unsigned char *>iv, len(iv), &self.ctr)
		if res != CRYPT_OK:
			raise CryptoError(res)
	
	cpdef ctr_encrypt(self, input):
		"""Encrypt a string in CTR mode."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = ctr_encrypt(<unsigned char *>input, <unsigned char*>output, length, &self.ctr)
		if res != CRYPT_OK:
			raise CryptoError(res)
		return output
	
	cpdef ctr_decrypt(self, input):
		"""Decrypt a string in CTR mode."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = ctr_decrypt(<unsigned char *>input, <unsigned char*>output, length, &self.ctr)
		if res != CRYPT_OK:
			raise CryptoError(res)
		return output
	
	cpdef ctr_done(self):
		cdef int res
		res = ctr_done(&self.ctr)
		if res != CRYPT_OK:
			raise CryptoError(res)
	cpdef cfb_get_iv(self):
		cdef int res
		cdef unsigned long length
		length = self.cipher.block_length
		iv = PyString_FromStringAndSize(NULL, length)
		res = cfb_getiv(<unsigned char *>iv, &length, &self.cfb)
		if res != CRYPT_OK:
			raise CryptoError(res)
		return iv
	
	cpdef cfb_set_iv(self, iv):
		cdef int res
		res = cfb_setiv(<unsigned char *>iv, len(iv), &self.cfb)
		if res != CRYPT_OK:
			raise CryptoError(res)
	
	cpdef cfb_encrypt(self, input):
		"""Encrypt a string in CFB mode."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = cfb_encrypt(<unsigned char *>input, <unsigned char*>output, length, &self.cfb)
		if res != CRYPT_OK:
			raise CryptoError(res)
		return output
	
	cpdef cfb_decrypt(self, input):
		"""Decrypt a string in CFB mode."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = cfb_decrypt(<unsigned char *>input, <unsigned char*>output, length, &self.cfb)
		if res != CRYPT_OK:
			raise CryptoError(res)
		return output
	
	cpdef cfb_done(self):
		cdef int res
		res = cfb_done(&self.cfb)
		if res != CRYPT_OK:
			raise CryptoError(res)
	cpdef ofb_get_iv(self):
		cdef int res
		cdef unsigned long length
		length = self.cipher.block_length
		iv = PyString_FromStringAndSize(NULL, length)
		res = ofb_getiv(<unsigned char *>iv, &length, &self.ofb)
		if res != CRYPT_OK:
			raise CryptoError(res)
		return iv
	
	cpdef ofb_set_iv(self, iv):
		cdef int res
		res = ofb_setiv(<unsigned char *>iv, len(iv), &self.ofb)
		if res != CRYPT_OK:
			raise CryptoError(res)
	
	cpdef ofb_encrypt(self, input):
		"""Encrypt a string in OFB mode."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = ofb_encrypt(<unsigned char *>input, <unsigned char*>output, length, &self.ofb)
		if res != CRYPT_OK:
			raise CryptoError(res)
		return output
	
	cpdef ofb_decrypt(self, input):
		"""Decrypt a string in OFB mode."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = ofb_decrypt(<unsigned char *>input, <unsigned char*>output, length, &self.ofb)
		if res != CRYPT_OK:
			raise CryptoError(res)
		return output
	
	cpdef ofb_done(self):
		cdef int res
		res = ofb_done(&self.ofb)
		if res != CRYPT_OK:
			raise CryptoError(res)
	
	# ==== END =====
		
	



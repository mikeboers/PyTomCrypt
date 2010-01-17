



cdef extern from "stdlib.h":

	void * malloc(int size)
	void free(void * ptr)


cdef extern from "Python.h":

	object PyString_FromStringAndSize(char *s, Py_ssize_t len)


cdef extern from "tomcrypt.h":

	int CRYPT_OK
	int CTR_COUNTER_BIG_ENDIAN
	char * error_to_string(int err)
	
	# Generic symmetric key, and for all of the supported modes.
	ctypedef struct symmetric_ofb "symmetric_OFB":
		pass
	ctypedef struct symmetric_cbc "symmetric_CBC":
		pass
	ctypedef struct symmetric_cfb "symmetric_CFB":
		pass
	ctypedef struct symmetric_ecb "symmetric_ECB":
		pass
	ctypedef struct symmetric_ctr "symmetric_CTR":
		pass
	
	# Pull in all the cipher functions for all the modes.
	int ecb_start(int cipher, unsigned char *key, int keylen, int num_rounds, symmetric_ecb *ecb)
	int ctr_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, int ctr_mode, symmetric_ctr *ctr)
	int ofb_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, symmetric_ofb *ofb)
	int cbc_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, symmetric_cbc *cbc)
	int cfb_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, symmetric_cfb *cfb)
	int ofb_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_ofb *ofb)
	int ofb_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_ofb *ofb)
	int ofb_done(symmetric_ofb *ofb)
	int cbc_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_cbc *cbc)
	int cbc_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_cbc *cbc)
	int cbc_done(symmetric_cbc *cbc)
	int cfb_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_cfb *cfb)
	int cfb_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_cfb *cfb)
	int cfb_done(symmetric_cfb *cfb)
	int ecb_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_ecb *ecb)
	int ecb_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_ecb *ecb)
	int ecb_done(symmetric_ecb *ecb)
	int ctr_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_ctr *ctr)
	int ctr_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_ctr *ctr)
	int ctr_done(symmetric_ctr *ctr)
	int ofb_getiv(unsigned char *iv, unsigned long *len, symmetric_ofb *ofb)
	int ofb_setiv(unsigned char *iv, unsigned long len, symmetric_ofb *ofb)
	int cbc_getiv(unsigned char *iv, unsigned long *len, symmetric_cbc *cbc)
	int cbc_setiv(unsigned char *iv, unsigned long len, symmetric_cbc *cbc)
	int cfb_getiv(unsigned char *iv, unsigned long *len, symmetric_cfb *cfb)
	int cfb_setiv(unsigned char *iv, unsigned long len, symmetric_cfb *cfb)
	int ctr_getiv(unsigned char *iv, unsigned long *len, symmetric_ctr *ctr)
	int ctr_setiv(unsigned char *iv, unsigned long len, symmetric_ctr *ctr)
	
	# Cipher descriptor.
	cdef struct cipher_desc "ltc_cipher_descriptor":
		char * name
		int min_key_length
		int max_key_length
		int block_length
		int default_rounds
		int keysize(int *keysize)
		# int setup(char *key, int keylen, int rounds, symmetric_key *skey)
	
	# The array which contains the descriptors once setup.
	cipher_desc cipher_descriptors "cipher_descriptor" []
	
	# The descriptors themselves.
	cipher_desc aes_desc
	int aes_test()
	cipher_desc des_desc
	int des_test()
	cipher_desc blowfish_desc
	int blowfish_test()
		
	# Functions for registering and finding the registered ciphers.
	int register_cipher(cipher_desc *cipher)
	int find_cipher(char * name)


# Register all of the ciphers.
register_cipher(&aes_desc)
register_cipher(&des_desc)
register_cipher(&blowfish_desc)


def test():
	"""Run the internal tests."""
	cdef int res
	res = aes_test()
	if res != CRYPT_OK:
		raise CipherError(res)
	res = des_test()
	if res != CRYPT_OK:
		raise CipherError(res)
	res = blowfish_test()
	if res != CRYPT_OK:
		raise CipherError(res)
		

cdef class CipherDesc(object):
	
	cdef int cipher_i
	cdef cipher_desc cipher
	
	def __init__(self, cipher):
		self.cipher_i = find_cipher(cipher)
		if self.cipher_i < 0:
			raise ValueError('could not find %r' % cipher)
		self.cipher = cipher_descriptors[self.cipher_i]
		
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
	
	def keysize(self, keysize):
		cdef int out
		out = keysize
		check_for_error(self.cipher.keysize(&out))
		return out
	
	def __call__(self, key, iv='', mode='cbc'):
		return Cipher(key, iv='', cipher=self.name, mode='cbc')
	

modes = {'ofb': 4, 'cbc': 1, 'cfb': 3, 'ecb': 0, 'ctr': 2}
simple_modes = {'ofb': 4, 'cbc': 1, 'cfb': 3}
iv_modes = {'ofb': 4, 'cbc': 1, 'cfb': 3, 'ctr': 2}
OFB = 'ofb'
CBC = 'cbc'
CFB = 'cfb'
ECB = 'ecb'
CTR = 'ctr'

ciphers = ['aes', 'des', 'blowfish']
AES = CipherDesc('aes')
DES = CipherDesc('des')
BLOWFISH = CipherDesc('blowfish')

class CipherError(Exception):
	
	def __init__(self, err):
		Exception.__init__(self, error_to_string(err), err)


cdef check_for_error(int res):
	if res != CRYPT_OK:
		raise CipherError(res)


cdef class Cipher(CipherDesc):
	
	cdef void *symmetric
	cdef object mode
	cdef int mode_i
	
	def __init__(self, key, iv='', cipher='aes', mode='cbc'):
		if mode not in modes:
			raise CipherError('no more %r' % mode)
		self.mode_i = modes[mode]	
		self.mode = mode
		
		CipherDesc.__init__(self, cipher)
		self.symmetric = NULL
		self.start(key, iv)
		
	cpdef start(self, key, iv=''):
		# Both the key and the iv are "const" for the start functions, so we
		# don't need to worry about making unique ones.
		iv = iv + ('\0' * self.cipher.block_length)
		
		if self.symmetric != NULL:
			free(self.symmetric)
		
		if self.mode_i == 0:
			self.symmetric = malloc(sizeof(symmetric_ecb))
			check_for_error(ecb_start(self.cipher_i, key, len(key), 0, <symmetric_ecb*>self.symmetric))
		if self.mode_i == 1:
			self.symmetric = malloc(sizeof(symmetric_cbc))
			check_for_error(cbc_start(self.cipher_i, iv, key, len(key), 0, <symmetric_cbc*>self.symmetric))
		if self.mode_i == 2:
			self.symmetric = malloc(sizeof(symmetric_ctr))
			check_for_error(ctr_start(self.cipher_i, iv, key, len(key), 0, CTR_COUNTER_BIG_ENDIAN, <symmetric_ctr*>self.symmetric))
		if self.mode_i == 3:
			self.symmetric = malloc(sizeof(symmetric_cfb))
			check_for_error(cfb_start(self.cipher_i, iv, key, len(key), 0, <symmetric_cfb*>self.symmetric))
		if self.mode_i == 4:
			self.symmetric = malloc(sizeof(symmetric_ofb))
			check_for_error(ofb_start(self.cipher_i, iv, key, len(key), 0, <symmetric_ofb*>self.symmetric))
	
	def __dealloc__(self):
		if self.symmetric != NULL:
			free(self.symmetric)
	
	cpdef get_iv(self):
		cdef unsigned long length
		length = self.cipher.block_length
		iv = PyString_FromStringAndSize(NULL, length)
		if self.mode_i == 1:
			check_for_error(cbc_getiv(<unsigned char *>iv, &length, <symmetric_cbc*>self.symmetric))
			return iv
		if self.mode_i == 2:
			check_for_error(ctr_getiv(<unsigned char *>iv, &length, <symmetric_ctr*>self.symmetric))
			return iv
		if self.mode_i == 3:
			check_for_error(cfb_getiv(<unsigned char *>iv, &length, <symmetric_cfb*>self.symmetric))
			return iv
		if self.mode_i == 4:
			check_for_error(ofb_getiv(<unsigned char *>iv, &length, <symmetric_ofb*>self.symmetric))
			return iv
		raise CipherError('%r mode does not use an IV' % self.mode)
	
	cpdef set_iv(self, iv):	
		if self.mode_i == 1:
			check_for_error(cbc_setiv(<unsigned char *>iv, len(iv), <symmetric_cbc*>self.symmetric))
			return
		if self.mode_i == 2:
			check_for_error(ctr_setiv(<unsigned char *>iv, len(iv), <symmetric_ctr*>self.symmetric))
			return
		if self.mode_i == 3:
			check_for_error(cfb_setiv(<unsigned char *>iv, len(iv), <symmetric_cfb*>self.symmetric))
			return
		if self.mode_i == 4:
			check_for_error(ofb_setiv(<unsigned char *>iv, len(iv), <symmetric_ofb*>self.symmetric))
			return
		raise CipherError('%r mode does not use an IV' % self.mode)

	cpdef done(self):
		if self.mode_i == 0:
			check_for_error(ecb_done(<symmetric_ecb*>self.symmetric))
			return
		if self.mode_i == 1:
			check_for_error(cbc_done(<symmetric_cbc*>self.symmetric))
			return
		if self.mode_i == 2:
			check_for_error(ctr_done(<symmetric_ctr*>self.symmetric))
			return
		if self.mode_i == 3:
			check_for_error(cfb_done(<symmetric_cfb*>self.symmetric))
			return
		if self.mode_i == 4:
			check_for_error(ofb_done(<symmetric_ofb*>self.symmetric))
			return
	
	cpdef encrypt(self, input):
		"""Encrypt a string."""
		cdef int length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		if self.mode_i == 0:
			check_for_error(ecb_encrypt(<unsigned char *>input, <unsigned char*>output, length, <symmetric_ecb*>self.symmetric))
			return output
		if self.mode_i == 1:
			check_for_error(cbc_encrypt(<unsigned char *>input, <unsigned char*>output, length, <symmetric_cbc*>self.symmetric))
			return output
		if self.mode_i == 2:
			check_for_error(ctr_encrypt(<unsigned char *>input, <unsigned char*>output, length, <symmetric_ctr*>self.symmetric))
			return output
		if self.mode_i == 3:
			check_for_error(cfb_encrypt(<unsigned char *>input, <unsigned char*>output, length, <symmetric_cfb*>self.symmetric))
			return output
		if self.mode_i == 4:
			check_for_error(ofb_encrypt(<unsigned char *>input, <unsigned char*>output, length, <symmetric_ofb*>self.symmetric))
			return output
	
	cpdef decrypt(self, input):
		"""Decrypt a string."""
		cdef int length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		if self.mode_i == 0:
			check_for_error(ecb_decrypt(<unsigned char *>input, <unsigned char*>output, length, <symmetric_ecb*>self.symmetric))
			return output
		if self.mode_i == 1:
			check_for_error(cbc_decrypt(<unsigned char *>input, <unsigned char*>output, length, <symmetric_cbc*>self.symmetric))
			return output
		if self.mode_i == 2:
			check_for_error(ctr_decrypt(<unsigned char *>input, <unsigned char*>output, length, <symmetric_ctr*>self.symmetric))
			return output
		if self.mode_i == 3:
			check_for_error(cfb_decrypt(<unsigned char *>input, <unsigned char*>output, length, <symmetric_cfb*>self.symmetric))
			return output
		if self.mode_i == 4:
			check_for_error(ofb_decrypt(<unsigned char *>input, <unsigned char*>output, length, <symmetric_ofb*>self.symmetric))
			return output
	
		
	



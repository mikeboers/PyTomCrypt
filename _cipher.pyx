
modes = ('ecb', 'cbc', 'ctr', 'cfb', 'ofb')
simple_modes = ('cbc', 'cfb', 'ofb')
iv_modes = ('ctr', 'cbc', 'cfb', 'ofb')
ciphers = ('aes', 'blowfish', 'des', 'twofish')


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
		int keysize(int *keysize)
		# int setup(char *key, int keylen, int rounds, symmetric_key *skey)
	
	# The array which contains the descriptors once setup.
	cipher_desc cipher_descriptors "cipher_descriptor" []
	
	# The descriptors themselves.
	cipher_desc aes_desc
	int aes_test()
	cipher_desc blowfish_desc
	int blowfish_test()
	cipher_desc des_desc
	int des_test()
	cipher_desc twofish_desc
	int twofish_test()
		
	# Functions for registering and finding the registered ciphers.
	int register_cipher(cipher_desc *cipher)
	int find_cipher(char * name)


class CipherError(Exception):
	def __init__(self, err):
		if isinstance(err, int):
			Exception.__init__(self, error_to_string(err))
		else:
			Exception.__init__(self, err)
		


cdef check_for_error(int res):
	if res != CRYPT_OK:
		raise CipherError(res)


# Register all of the ciphers.
register_cipher(&aes_desc)
register_cipher(&blowfish_desc)
register_cipher(&des_desc)
register_cipher(&twofish_desc)


def test():
	"""Run the internal tests."""
	cdef int res
	res = aes_test()
	if res != CRYPT_OK:
		raise CipherError(res)
	res = blowfish_test()
	if res != CRYPT_OK:
		raise CipherError(res)
	res = des_test()
	if res != CRYPT_OK:
		raise CipherError(res)
	res = twofish_test()
	if res != CRYPT_OK:
		raise CipherError(res)
		

cdef class CipherDesc(object):
	
	cdef int cipher_i
	cdef cipher_desc cipher
	
	def __init__(self, cipher):
		self.cipher_i = find_cipher(cipher)
		if self.cipher_i < 0:
			raise CipherError('could not find %r' % cipher)
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
	

try:
	AES = CipherDesc('aes')
except CipherError:
	pass
try:
	BLOWFISH = CipherDesc('blowfish')
except CipherError:
	pass
try:
	DES = CipherDesc('des')
except CipherError:
	pass
try:
	TWOFISH = CipherDesc('twofish')
except CipherError:
	pass




cipher_classes = {}

cdef class ECB(CipherDesc):
	
	cdef symmetric_ecb symmetric
		
	def __init__(self, key, iv='', cipher='aes', mode=None):
		if mode is not None and mode != 'ecb':
			raise CipherError('wrong mode %r' % mode)
		CipherDesc.__init__(self, cipher)
		self.start(key, iv)
		
	cpdef start(self, key, iv=''):
		# Both the key and the iv are "const" for the start functions, so we
		# don't need to worry about making unique ones.
		iv = iv + ('\0' * self.cipher.block_length)
		check_for_error(ecb_start(self.cipher_i, key, len(key), 0, &self.symmetric))
	
	cpdef done(self):
		check_for_error(ecb_done(&self.symmetric))
	
	cpdef encrypt(self, input):
		"""Encrypt a string."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = ecb_encrypt(<unsigned char *>input, <unsigned char*>output, length, &self.symmetric)
		if res != CRYPT_OK:
			if length % self.cipher.block_length:
				raise CipherError('input not multiple of block length')
			raise CipherError(res)
		return output
	
	cpdef decrypt(self, input):
		"""Decrypt a string."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = ecb_decrypt(<unsigned char *>input, <unsigned char*>output, length, &self.symmetric)
		if res != CRYPT_OK:
			if length % self.cipher.block_length:
				raise CipherError('input not multiple of block length')
			raise CipherError(res)
		return output
	
	
cipher_classes['ecb'] = ECB


cdef class CBC(CipherDesc):
	
	cdef symmetric_cbc symmetric
		
	def __init__(self, key, iv='', cipher='aes', mode=None):
		if mode is not None and mode != 'cbc':
			raise CipherError('wrong mode %r' % mode)
		CipherDesc.__init__(self, cipher)
		self.start(key, iv)
		
	cpdef start(self, key, iv=''):
		# Both the key and the iv are "const" for the start functions, so we
		# don't need to worry about making unique ones.
		iv = iv + ('\0' * self.cipher.block_length)
		check_for_error(cbc_start(self.cipher_i, iv, key, len(key), 0, &self.symmetric))
	
	cpdef get_iv(self):
		cdef unsigned long length
		length = self.cipher.block_length
		iv = PyString_FromStringAndSize(NULL, length)
		check_for_error(cbc_getiv(<unsigned char *>iv, &length, &self.symmetric))
		return iv
	
	cpdef set_iv(self, iv):	
		check_for_error(cbc_setiv(<unsigned char *>iv, len(iv), &self.symmetric))
	
	cpdef done(self):
		check_for_error(cbc_done(&self.symmetric))
	
	cpdef encrypt(self, input):
		"""Encrypt a string."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = cbc_encrypt(<unsigned char *>input, <unsigned char*>output, length, &self.symmetric)
		if res != CRYPT_OK:
			if length % self.cipher.block_length:
				raise CipherError('input not multiple of block length')
			raise CipherError(res)
		return output
	
	cpdef decrypt(self, input):
		"""Decrypt a string."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = cbc_decrypt(<unsigned char *>input, <unsigned char*>output, length, &self.symmetric)
		if res != CRYPT_OK:
			if length % self.cipher.block_length:
				raise CipherError('input not multiple of block length')
			raise CipherError(res)
		return output
	
	
cipher_classes['cbc'] = CBC


cdef class CTR(CipherDesc):
	
	cdef symmetric_ctr symmetric
		
	def __init__(self, key, iv='', cipher='aes', mode=None):
		if mode is not None and mode != 'ctr':
			raise CipherError('wrong mode %r' % mode)
		CipherDesc.__init__(self, cipher)
		self.start(key, iv)
		
	cpdef start(self, key, iv=''):
		# Both the key and the iv are "const" for the start functions, so we
		# don't need to worry about making unique ones.
		iv = iv + ('\0' * self.cipher.block_length)
		check_for_error(ctr_start(self.cipher_i, iv, key, len(key), 0, CTR_COUNTER_BIG_ENDIAN, &self.symmetric))
	
	cpdef get_iv(self):
		cdef unsigned long length
		length = self.cipher.block_length
		iv = PyString_FromStringAndSize(NULL, length)
		check_for_error(ctr_getiv(<unsigned char *>iv, &length, &self.symmetric))
		return iv
	
	cpdef set_iv(self, iv):	
		check_for_error(ctr_setiv(<unsigned char *>iv, len(iv), &self.symmetric))
	
	cpdef done(self):
		check_for_error(ctr_done(&self.symmetric))
	
	cpdef encrypt(self, input):
		"""Encrypt a string."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = ctr_encrypt(<unsigned char *>input, <unsigned char*>output, length, &self.symmetric)
		if res != CRYPT_OK:
			if length % self.cipher.block_length:
				raise CipherError('input not multiple of block length')
			raise CipherError(res)
		return output
	
	cpdef decrypt(self, input):
		"""Decrypt a string."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = ctr_decrypt(<unsigned char *>input, <unsigned char*>output, length, &self.symmetric)
		if res != CRYPT_OK:
			if length % self.cipher.block_length:
				raise CipherError('input not multiple of block length')
			raise CipherError(res)
		return output
	
	
cipher_classes['ctr'] = CTR


cdef class CFB(CipherDesc):
	
	cdef symmetric_cfb symmetric
		
	def __init__(self, key, iv='', cipher='aes', mode=None):
		if mode is not None and mode != 'cfb':
			raise CipherError('wrong mode %r' % mode)
		CipherDesc.__init__(self, cipher)
		self.start(key, iv)
		
	cpdef start(self, key, iv=''):
		# Both the key and the iv are "const" for the start functions, so we
		# don't need to worry about making unique ones.
		iv = iv + ('\0' * self.cipher.block_length)
		check_for_error(cfb_start(self.cipher_i, iv, key, len(key), 0, &self.symmetric))
	
	cpdef get_iv(self):
		cdef unsigned long length
		length = self.cipher.block_length
		iv = PyString_FromStringAndSize(NULL, length)
		check_for_error(cfb_getiv(<unsigned char *>iv, &length, &self.symmetric))
		return iv
	
	cpdef set_iv(self, iv):	
		check_for_error(cfb_setiv(<unsigned char *>iv, len(iv), &self.symmetric))
	
	cpdef done(self):
		check_for_error(cfb_done(&self.symmetric))
	
	cpdef encrypt(self, input):
		"""Encrypt a string."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = cfb_encrypt(<unsigned char *>input, <unsigned char*>output, length, &self.symmetric)
		if res != CRYPT_OK:
			if length % self.cipher.block_length:
				raise CipherError('input not multiple of block length')
			raise CipherError(res)
		return output
	
	cpdef decrypt(self, input):
		"""Decrypt a string."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = cfb_decrypt(<unsigned char *>input, <unsigned char*>output, length, &self.symmetric)
		if res != CRYPT_OK:
			if length % self.cipher.block_length:
				raise CipherError('input not multiple of block length')
			raise CipherError(res)
		return output
	
	
cipher_classes['cfb'] = CFB


cdef class OFB(CipherDesc):
	
	cdef symmetric_ofb symmetric
		
	def __init__(self, key, iv='', cipher='aes', mode=None):
		if mode is not None and mode != 'ofb':
			raise CipherError('wrong mode %r' % mode)
		CipherDesc.__init__(self, cipher)
		self.start(key, iv)
		
	cpdef start(self, key, iv=''):
		# Both the key and the iv are "const" for the start functions, so we
		# don't need to worry about making unique ones.
		iv = iv + ('\0' * self.cipher.block_length)
		check_for_error(ofb_start(self.cipher_i, iv, key, len(key), 0, &self.symmetric))
	
	cpdef get_iv(self):
		cdef unsigned long length
		length = self.cipher.block_length
		iv = PyString_FromStringAndSize(NULL, length)
		check_for_error(ofb_getiv(<unsigned char *>iv, &length, &self.symmetric))
		return iv
	
	cpdef set_iv(self, iv):	
		check_for_error(ofb_setiv(<unsigned char *>iv, len(iv), &self.symmetric))
	
	cpdef done(self):
		check_for_error(ofb_done(&self.symmetric))
	
	cpdef encrypt(self, input):
		"""Encrypt a string."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = ofb_encrypt(<unsigned char *>input, <unsigned char*>output, length, &self.symmetric)
		if res != CRYPT_OK:
			if length % self.cipher.block_length:
				raise CipherError('input not multiple of block length')
			raise CipherError(res)
		return output
	
	cpdef decrypt(self, input):
		"""Decrypt a string."""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = ofb_decrypt(<unsigned char *>input, <unsigned char*>output, length, &self.symmetric)
		if res != CRYPT_OK:
			if length % self.cipher.block_length:
				raise CipherError('input not multiple of block length')
			raise CipherError(res)
		return output
	
	
cipher_classes['ofb'] = OFB


def Cipher(key, iv='', cipher='aes', mode='ecb'):
	return cipher_classes[mode](key, iv, cipher, mode)


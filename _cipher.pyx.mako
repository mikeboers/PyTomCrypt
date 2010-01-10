
<%!

modes = 'ecb cbc ctr cfb ofb'.split()
iv_modes = 'ctr cbc cfb ofb'.split()
simple_modes = 'cbc cfb ofb'.split()
ciphers = 'aes des blowfish'.split()

%>

modes = ${repr(modes)}
simple_modes = ${repr(simple_modes)}
ciphers = ${repr(ciphers)}

cdef extern from "Python.h":

	object PyString_FromStringAndSize(char *s, Py_ssize_t len)

cdef extern from "tomcrypt.h":

	int CRYPT_OK
	int CTR_COUNTER_BIG_ENDIAN
	char * error_to_string(int err)
	
	# Generic symmetric key, and for all of the supported modes.
	% for name in modes:
	ctypedef struct symmetric_${name} "symmetric_${name.upper()}":
		pass
	% endfor
	
	# Pull in all the cipher functions for all the modes.
	int ecb_start(int cipher, unsigned char *key, int keylen, int num_rounds, symmetric_ecb *ecb)
	int ctr_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, int ctr_mode, symmetric_ctr *ctr)
	% for name in simple_modes:
	int ${name}_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, symmetric_${name} *${name})
	% endfor
	% for name in modes:
	int ${name}_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_${name} *${name})
	int ${name}_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_${name} *${name})
	int ${name}_done(symmetric_${name} *${name})
	% endfor
	% for name in iv_modes:
	int ${name}_getiv(unsigned char *iv, unsigned long *len, symmetric_${name} *${name})
	int ${name}_setiv(unsigned char *iv, unsigned long len, symmetric_${name} *${name})
	% endfor
	
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
	% for name in ciphers:
	cipher_desc ${name}_desc
	int ${name}_test()
	% endfor
		
	# Functions for registering and finding the registered ciphers.
	int register_cipher(cipher_desc *cipher)
	int find_cipher(char * name)


# Register all of the ciphers.
% for name in ciphers:
register_cipher(&${name}_desc)
% endfor


def test():
	"""Run the internal tests."""
	cdef int res
	% for name in ciphers:
	res = ${name}_test()
	if res != CRYPT_OK:
		raise CryptoError(res)
	% endfor
		

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
	
	
% for name in ciphers:
${name} = CipherDesc('${name}')
% endfor

class CryptoError(Exception):
	
	def __init__(self, err):
		Exception.__init__(self, error_to_string(err), err)


cdef int check_for_error(int res):
	if res != CRYPT_OK:
		raise CryptoError(res)
	return res


cdef class Cipher(CipherDesc):
	
	% for mode in modes:
	cdef symmetric_${mode} ${mode}
	% endfor
	
	def __init__(self, key, iv='', cipher='aes', mode='cbc'):		
		CipherDesc.__init__(self, cipher)
		self.start(key, iv)
		
	cpdef start(self, key, iv=''):
		# Both the key and the iv are "const" for the start functions, so we
		# don't need to worry about making unique ones.
		iv = iv + ('\0' * self.cipher.block_length)
		check_for_error(ecb_start(self.cipher_i, key, len(key), 0, &self.ecb))
		check_for_error(ctr_start(self.cipher_i, iv, key, len(key), 0, CTR_COUNTER_BIG_ENDIAN, &self.ctr))
		% for mode in simple_modes:
		check_for_error(${mode}_start(self.cipher_i, iv, key, len(key), 0, &self.${mode}))
		% endfor
	
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
	
	# ===== KEYSIZE / IV / ENCRYPTION / DECRYPTION FUNCTIONS =====
	
	% for mode in modes:
	% if mode in iv_modes:
	cpdef ${mode}_get_iv(self):
		cdef unsigned long length
		length = self.cipher.block_length
		iv = PyString_FromStringAndSize(NULL, length)
		check_for_error(${mode}_getiv(<unsigned char *>iv, &length, &self.${mode}))
		return iv
	
	cpdef ${mode}_set_iv(self, iv):
		check_for_error(${mode}_setiv(<unsigned char *>iv, len(iv), &self.${mode}))
	% endif	
	% for type in 'encrypt decrypt'.split():
	
	cpdef ${mode}_${type}(self, input):
		"""${type.capitalize()} a string in ${mode.upper()} mode."""
		cdef int length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		check_for_error(${mode}_${type}(<unsigned char *>input, <unsigned char*>output, length, &self.${mode}))
		return output
	% endfor
	
	cpdef ${mode}_done(self):
		check_for_error(${mode}_done(&self.${mode}))
	% endfor
	
	# ==== END =====
		
	


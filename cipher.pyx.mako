
<%!

modes = dict((k, i) for i, k in enumerate('ecb cbc ctr cfb ofb'.split()))
iv_modes = dict((k, modes[k]) for k in 'ctr cbc cfb ofb'.split())
simple_modes = dict((k, modes[k]) for k in 'cbc cfb ofb'.split())
ciphers = 'aes des blowfish'.split()

mode_items = list(sorted(modes.items(), key=lambda x: x[1]))

%>


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
	# Really these take <symmetric_${name} *>, but it doesn't seem to care,
	# and dispatching is made easier. Maybe takes 0.05% longer.
	int ${name}_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, void *${name})
	int ${name}_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, void *${name})
	int ${name}_done(void *${name})
	% endfor
	% for name in iv_modes:
	int ${name}_getiv(unsigned char *iv, unsigned long *len, void *${name})
	int ${name}_setiv(unsigned char *iv, unsigned long len, void *${name})
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
		raise Error(res)
	% endfor
		

cdef class Descriptor(object):
	
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
	

modes = ${repr(modes)}
simple_modes = ${repr(simple_modes)}
iv_modes = ${repr(iv_modes)}
% for k, v in modes.iteritems():
${k.upper()} = ${repr(k)}
% endfor

ciphers = ${repr(ciphers)}
% for name in ciphers:
${name.upper()} = Descriptor('${name}')
% endfor


class Error(Exception):
	def __init__(self, err):
		if isinstance(err, int):
			Exception.__init__(self, error_to_string(err))
		else:
			Exception.__init__(self, err)


cdef check_for_error(int res):
	if res != CRYPT_OK:
		raise Error(res)


# Define function pointer types for each of the functions that have common
# signatures.
ctypedef int (*all_crypt_pt)(unsigned char *, unsigned char *, unsigned long, void *)
ctypedef all_crypt_pt all_encrypt_pt
ctypedef all_crypt_pt all_decrypt_pt
ctypedef int (*all_getiv_pt)(unsigned char *, unsigned long *, void *)
ctypedef int (*all_setiv_pt)(unsigned char *, unsigned long  , void *)
ctypedef int (*all_done_pt)(void *)

# Arrays to hold the function pointers.
% for name in 'encrypt decrypt getiv setiv done'.split():
cdef all_${name}_pt all_${name}[${len(modes)}]
% endfor

# Assign the functions.
% for mode, i in modes.items():
all_encrypt[${i}] = ${mode}_encrypt
all_decrypt[${i}] = ${mode}_decrypt
% if mode in iv_modes:
all_getiv[${i}] = ${mode}_getiv
all_setiv[${i}] = ${mode}_setiv
% endif
all_done[${i}] = ${mode}_done
% endfor


cdef union symmetric_all:
	% for mode in modes:
	symmetric_${mode} ${mode}
	% endfor


cdef class Cipher(Descriptor):
	
	cdef symmetric_all symmetric
	cdef object mode
	cdef int mode_i
	
	def __init__(self, key, iv=None, cipher='', mode='ecb'):
		if mode not in modes:
			raise Error('no more %r' % mode)
		self.mode_i = modes[mode]	
		self.mode = mode
		Descriptor.__init__(self, cipher)
		self.start(key, iv)
		
	cpdef start(self, key, iv=None):
		# Both the key and the iv are "const" for the start functions, so we
		# don't need to worry about making unique ones.
		if iv is None:
			iv = '\0' * self.cipher.block_length
		if len(iv) != self.cipher.block_length:
			raise Error('iv must be %d bytes' % self.cipher.block_length)
		
		% for mode, i in mode_items:
		if self.mode_i == ${i}:
			% if mode == 'ecb':
			check_for_error(ecb_start(self.cipher_i, key, len(key), 0, <symmetric_${mode}*>&self.symmetric))
			% elif mode == 'ctr':
			check_for_error(ctr_start(self.cipher_i, iv, key, len(key), 0, CTR_COUNTER_BIG_ENDIAN, <symmetric_${mode}*>&self.symmetric))
			% else:
			check_for_error(${mode}_start(self.cipher_i, iv, key, len(key), 0, <symmetric_${mode}*>&self.symmetric))
			% endif
		% endfor
	
	cpdef get_iv(self):
		if all_getiv[self.mode_i] == NULL:
			raise Error('%r mode does not use an IV' % self.mode)
		cdef unsigned long length
		length = self.cipher.block_length
		iv = PyString_FromStringAndSize(NULL, length)
		check_for_error(all_getiv[self.mode_i](<unsigned char *>iv, &length, &self.symmetric))
		return iv
	
	cpdef set_iv(self, iv):	
		if all_getiv[self.mode_i] == NULL:
			raise Error('%r mode does not use an IV' % self.mode)
		check_for_error(all_setiv[self.mode_i](<unsigned char *>iv, len(iv), &self.symmetric))

	cpdef done(self):
		check_for_error(all_done[self.mode_i](&self.symmetric))
	
	% for type in 'encrypt decrypt'.split():
	cpdef ${type}(self, input):
		"""${type.capitalize()} a string."""
		cdef int length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		check_for_error(all_${type}[self.mode_i](<unsigned char *>input, <unsigned char*>output, length, &self.symmetric))
		return output
	
	% endfor
		


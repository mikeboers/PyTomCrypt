<%!

modes = tuple('ecb cbc ctr cfb ofb'.split())
block_modes = set('ecb cbc'.split())
iv_modes = tuple('ctr cbc cfb ofb'.split())
simple_modes = tuple('cbc cfb ofb'.split())
if True:
	ciphers = tuple('''
		aes
		anubis
		blowfish
		cast5
		des
		des3
		kasumi
		khazad
		kseed
		noekeon
		rc2
		rc5
		rc6
		saferp
		twofish
		xtea'''.strip().split())
else:
	ciphers = tuple('''
		aes
		blowfish
		des
		twofish'''.strip().split())

%>


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


class Error(Exception):
	def __init__(self, err):
		if isinstance(err, int):
			Exception.__init__(self, error_to_string(err))
		else:
			Exception.__init__(self, err)


cdef check_for_error(int res):
	if res != CRYPT_OK:
		raise Error(res)




def test():
	"""Run the internal tests."""
	cdef int res
	% for name in ciphers:
	res = ${name}_test()
	if res != CRYPT_OK:
		raise Error(res)
	% endfor
		

cdef class Descriptor(object):
	
	cdef int cipher_idx
	cdef cipher_desc cipher
	
	def __init__(self, cipher):
		self.cipher_idx = find_cipher(cipher)
		if self.cipher_idx < 0:
			raise Error('could not find %r' % cipher)
		self.cipher = cipher_descriptors[self.cipher_idx]
	
	def __repr__(self):
		## This is some uglyness just so Mako doesn't freak out at the <%.
		return ${repr('<%s.%s for %r at 0x%x>')} % (self.__class__.__module__,
			self.__class__.__name__, self.name, id(self))
		
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
	
	def __call__(self, key, iv='', **kwargs):
		return Cipher(key, iv='', cipher=self.name, **kwargs)


# Register all of the ciphers.
ciphers = {}
% for name in ciphers:

register_cipher(&${name}_desc)
try:
	ciphers[${repr(name.upper())}] = ${name.upper()} = Descriptor(${repr(name)})
except Error:
	pass
% endfor


% for mode in modes:
cdef class ${mode.upper()}(Descriptor):
	
	cdef symmetric_${mode} symmetric
		
	def __init__(self, key, iv='', cipher='aes', mode=None):
		if mode is not None and mode != ${repr(mode)}:
			raise Error('wrong mode %r' % mode)
		Descriptor.__init__(self, cipher)
		self.start(key, iv)
		
	cpdef start(self, key, iv=''):
		# Both the key and the iv are "const" for the start functions, so we
		# don't need to worry about making unique ones.
		iv = iv + ('\0' * self.cipher.block_length)
		% if mode == 'ecb':
		check_for_error(ecb_start(self.cipher_idx, key, len(key), 0, &self.symmetric))
		% elif mode == 'ctr':
		check_for_error(ctr_start(self.cipher_idx, iv, key, len(key), 0, CTR_COUNTER_BIG_ENDIAN, &self.symmetric))
		% else:
		check_for_error(${mode}_start(self.cipher_idx, iv, key, len(key), 0, &self.symmetric))
		% endif
	
	% if mode in iv_modes:
	cpdef get_iv(self):
		cdef unsigned long length
		length = self.cipher.block_length
		iv = PyString_FromStringAndSize(NULL, length)
		check_for_error(${mode}_getiv(<unsigned char *>iv, &length, &self.symmetric))
		return iv
	
	cpdef set_iv(self, iv):	
		check_for_error(${mode}_setiv(<unsigned char *>iv, len(iv), &self.symmetric))
	
	% endif
	cpdef done(self):
		check_for_error(${mode}_done(&self.symmetric))
	
	% for type in 'encrypt decrypt'.split():
	cpdef ${type}(self, input):
		"""${type.capitalize()} a string.
		
		% if mode in block_modes:
		Input must be a multiple of the block length.
		
		% endif
		"""
		cdef int res, length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		res = ${mode}_${type}(<unsigned char *>input, <unsigned char*>output, length, &self.symmetric)
		if res != CRYPT_OK:
			% if mode in block_modes:
			if length % self.cipher.block_length:
				raise Error('input not multiple of block length')
			% endif
			raise Error(res)
		return output
	
	% endfor

% endfor
modes = dict(
% for mode in modes:
	${mode}=${mode.upper()},
% endfor
)


def Cipher(key, iv='', cipher='aes', mode='ecb'):
	return modes[mode.lower()](key, iv, cipher, mode)


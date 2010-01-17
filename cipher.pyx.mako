
<%!

ALL_CIPHERS = False

modes = dict((k, i) for i, k in enumerate('ecb cbc ctr cfb ofb lrw f8'.split()))
no_iv_modes = dict((k, modes[k]) for k in 'ecb'.split())
iv_modes = dict((k, modes[k]) for k in modes if k not in no_iv_modes)
simple_modes = dict((k, modes[k]) for k in 'cbc cfb ofb'.split())

mode_items = list(sorted(modes.items(), key=lambda x: x[1]))

if ALL_CIPHERS:
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
		des'''.strip().split())

%>


from common cimport *


cdef extern from "tomcrypt.h":

	int CTR_COUNTER_BIG_ENDIAN
	
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
	int lrw_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, unsigned char *tweak, int num_rounds, symmetric_lrw *lrw)
	int f8_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, unsigned char *salt_key, int skeylen, int num_rounds, symmetric_f8 *f8)
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



class Error(Exception):
	def __init__(self, err):
		if isinstance(err, int):
			Exception.__init__(self, error_to_string(err))
		else:
			Exception.__init__(self, err)


# Wrap EVERY call to tomcryptlib in this function!
cdef check_for_error(int res):
	if res != CRYPT_OK:
		raise Error(res)


# Register all of the ciphers.
# We don't really need to worry about doing this as they are needed as this
# doesn't take very long at all.
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
	
	cdef int cipher_idx
	cdef cipher_desc cipher
	
	def __init__(self, cipher):
		self.cipher_idx = find_cipher(cipher)
		if self.cipher_idx < 0:
			raise ValueError('could not find %r' % cipher)
		self.cipher = cipher_descriptors[self.cipher_idx]
		
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
	
	def __call__(self, key, **kwargs):
		return Cipher(key, cipher=self.name, **kwargs)
	






# Define function pointer types for each of the functions that have common
# signatures.
ctypedef int (*all_crypt_pt)(unsigned char *, unsigned char *, unsigned long, void *)
ctypedef all_crypt_pt all_encrypt_pt
ctypedef all_crypt_pt all_decrypt_pt
ctypedef int (*all_getiv_pt)(unsigned char *, unsigned long *, void *)
ctypedef int (*all_setiv_pt)(unsigned char *, unsigned long  , void *)
ctypedef int (*all_done_pt)(void *)

# Setup arrays to hold the function pointers.
% for name in 'encrypt decrypt getiv setiv done'.split():
cdef all_${name}_pt all_${name}[${len(modes)}]
% endfor

% for mode, i in mode_items:
all_encrypt[${i}] = ${mode}_encrypt
all_decrypt[${i}] = ${mode}_decrypt
% if mode in iv_modes:
all_getiv[${i}] = ${mode}_getiv
all_setiv[${i}] = ${mode}_setiv
% endif
all_done[${i}] = ${mode}_done
% endfor


# Define a type to masquarade as ANY of the mode states.
cdef union symmetric_all:
	% for mode in modes:
	symmetric_${mode} ${mode}
	% endfor


cdef class Cipher(Descriptor):
	
	cdef symmetric_all state
	cdef object _mode
	cdef int mode_i
	
	def __init__(self, key, iv=None, cipher='aes', mode='ecb', **kwargs):
		self._mode = str(mode).lower()
		## We must keep these indices as magic numbers in the source.
		self.mode_i = {
		% for mode, i in mode_items:
			${repr(mode)}: ${i},
		% endfor
		}.get(self._mode, -1)
		if self.mode_i < 0:
			raise Error('no mode %r' % mode)
		Descriptor.__init__(self, cipher)
		self.start(key, iv, **kwargs)
	
	def __repr__(self):
		return ${repr('<%s.%s with %s in %s mode at 0x%x>')} % (
			self.__class__.__module__, self.__class__.__name__, self.name,
			self.mode, id(self))
	
	@property
	def mode(self):
		return self._mode
	
	def start(self, key, iv=None, **kwargs):
		# Both the key and the iv are "const" for the start functions, so we
		# don't need to worry about making unique ones.
		
		if iv is None:
			iv = '\0' * self.cipher.block_length
		if not isinstance(iv, basestring) or len(iv) != self.cipher.block_length:
			raise Error('iv must be %d bytes' % self.cipher.block_length)
		
		% for mode, i in mode_items:
		${'el' if i else ''}if self.mode_i == ${i}:
			% if mode == 'ecb':
			check_for_error(ecb_start(self.cipher_idx, key, len(key), 0, <symmetric_${mode}*>&self.state))
			
			% elif mode == 'ctr':
			check_for_error(ctr_start(self.cipher_idx, iv, key, len(key), 0, CTR_COUNTER_BIG_ENDIAN, <symmetric_${mode}*>&self.state))
			
			% elif mode in simple_modes:
			check_for_error(${mode}_start(self.cipher_idx, iv, key, len(key), 0, <symmetric_${mode}*>&self.state))
			
			% elif mode == 'lrw':
			tweak = kwargs.get('tweak')
			if not isinstance(tweak, basestring) or len(tweak) != 16:
				raise Error('tweak must be 16 byte string')
			check_for_error(${mode}_start(self.cipher_idx, iv, key, len(key), tweak, 0, <symmetric_${mode}*>&self.state))
			
			% elif mode == 'f8':
			salt_key = kwargs.get('salt_key')
			if not isinstance(salt_key, basestring):
				raise Error('salt_key must be a string')
			check_for_error(${mode}_start(self.cipher_idx, iv, key, len(key), salt_key, len(salt_key), 0, <symmetric_${mode}*>&self.state))
			
			% else:
			raise Error('no start for mode %r' % ${repr(mode)})
			
			% endif
		% endfor
	##
	cpdef get_iv(self):
		if all_getiv[self.mode_i] == NULL:
			raise Error('%r mode does not use an IV' % self.mode)
		cdef unsigned long length
		length = self.cipher.block_length
		iv = PyString_FromStringAndSize(NULL, length)
		check_for_error(all_getiv[self.mode_i](iv, &length, &self.state))
		return iv
	
	cpdef set_iv(self, iv):	
		if all_getiv[self.mode_i] == NULL:
			raise Error('%r mode does not use an IV' % self.mode)
		check_for_error(all_setiv[self.mode_i](iv, len(iv), &self.state))

	cpdef done(self):
		check_for_error(all_done[self.mode_i](&self.state))
	
	% for type in 'encrypt decrypt'.split():
	cpdef ${type}(self, input):
		"""${type.capitalize()} a string."""
		cdef int length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		check_for_error(all_${type}[self.mode_i](input, output, length, &self.state))
		return output
	
	% endfor

# This is just so that the API is pretty much the same for all the modules
# and to hashlib and hmac in the stdlib.
new = Cipher

# Make some descriptors and informational stuff for convenience
modes = ${repr(tuple(mode for mode, i in mode_items))}
simple_modes = ${repr(set(simple_modes))}
iv_modes = ${repr(set(iv_modes))}


% for mode, i in mode_items:
def ${mode.upper()}(key, *args, **kwargs):
	"""Cipher constructor for ${mode.upper()} mode."""
	return Cipher(key, *args, mode=${repr(mode)}, **kwargs)
% endfor


% for name in ciphers:
${name.upper()} = Descriptor('${name}')
% endfor
ciphers = (${', '.join(name.upper() for name in ciphers)})
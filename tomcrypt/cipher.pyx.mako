<%!

ALL_CIPHERS = True

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


include "common.pxi"


cdef extern from "tomcrypt.h":

	int CTR_COUNTER_BIG_ENDIAN
	
	# Symmetric state for all the modes.
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
	int ${name}_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_${name} *${name})
	int ${name}_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_${name} *${name})
	int ${name}_done(void *${name})
	% endfor
	% for name in iv_modes:
	int ${name}_getiv(unsigned char *iv, unsigned long *len, symmetric_${name} *${name})
	int ${name}_setiv(unsigned char *iv, unsigned long len, symmetric_${name} *${name})
	% endfor
	
	# Cipher descriptor.
	cdef struct cipher_desc "ltc_cipher_descriptor":
		char * name
		int min_key_size "min_key_length"
		int max_key_size "max_key_length"
		int block_size "block_length"
		int default_rounds
		int key_size "keysize" (int *key_size)
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
# We don't really need to worry about doing this as they are needed as this
# doesn't take very long at all.
cdef int max_cipher_idx = -1
% for name in ciphers:
max_cipher_idx = max(max_cipher_idx, register_cipher(&${name}_desc))
% endfor


def test():
	"""Run the internal tests."""
	cdef int res
	% for name in ciphers:
	check_for_error(${name}_test())
	% endfor
		

cdef class Descriptor(object):
	
	cdef int idx
	cdef cipher_desc desc
	
	def __init__(self, cipher):
		if isinstance(cipher, int):
			self.idx = cipher
		elif hasattr(cipher, 'cipher_idx'):
			self.idx = cipher.cipher_idx
		else:
			self.idx = find_cipher(cipher)
		if self.idx < 0 or self.idx > max_cipher_idx:
			raise ValueError('could not find %r' % cipher)
		self.desc = cipher_descriptors[self.idx]
	
	@property
	def cipher_idx(self):
		return self.idx
	
	% for name in 'name min_key_size max_key_size block_size default_rounds'.split():
	@property
	def ${name}(self):
		return self.desc.${name}
	
	% endfor
	##
	def key_size(self, key_size):
		cdef int out
		out = key_size
		check_for_error(self.desc.key_size(&out))
		return out
	
	def __call__(self, key, *args, **kwargs):
		return Cipher(key, *args, cipher=self.name, **kwargs)
	






# Define function pointer types for each of the functions that have common
# signatures, except they take a null pointer to the symmetric state.
ctypedef int (*all_crypt_pt)(unsigned char *, unsigned char *, unsigned long, void *)
ctypedef all_crypt_pt all_encrypt_pt
ctypedef all_crypt_pt all_decrypt_pt
ctypedef int (*all_getiv_pt)(unsigned char *, unsigned long *, void *)
ctypedef int (*all_setiv_pt)(unsigned char *, unsigned long  , void *)
ctypedef int (*all_done_pt)(void *)

# Setup arrays to hold the all the function pointers.
% for name in 'encrypt decrypt getiv setiv done'.split():
cdef all_${name}_pt all_${name}[${len(modes)}]
% endfor

# Define a inline wrapper function for each that properly casts the symmetric
# state to the right type. Then set these wrappers into the arrays.
% for mode, i in mode_items:
% for type in 'encrypt', 'decrypt':
cdef inline int null_${mode}_${type}(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return ${mode}_${type}(input, out, length, <symmetric_${mode}*>state)
all_${type}[${i}] = null_${mode}_${type}
% endfor
% if mode in iv_modes:
cdef inline int null_${mode}_getiv(unsigned char *output, unsigned long *outlen, void *state):
	return ${mode}_getiv(output, outlen, <symmetric_${mode}*>state)
cdef inline int null_${mode}_setiv(unsigned char *input, unsigned long inlen, void *state):
	return ${mode}_setiv(input, inlen, <symmetric_${mode}*>state)
all_getiv[${i}] = null_${mode}_getiv
all_setiv[${i}] = null_${mode}_setiv
% endif
cdef inline int null_${mode}_done(void *state):
	return ${mode}_done(<symmetric_${mode}*>state)
all_done[${i}] = null_${mode}_done
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
			iv = '\0' * self.desc.block_size
		if not isinstance(iv, basestring) or len(iv) != self.desc.block_size:
			raise Error('iv must be %d bytes' % self.desc.block_size)
		
		% for mode, i in mode_items:
		${'el' if i else ''}if self.mode_i == ${i}:
			% if mode == 'ecb':
			check_for_error(ecb_start(self.idx, key, len(key), 0, <symmetric_${mode}*>&self.state))
			
			% elif mode == 'ctr':
			check_for_error(ctr_start(self.idx, iv, key, len(key), 0, CTR_COUNTER_BIG_ENDIAN, <symmetric_${mode}*>&self.state))
			
			% elif mode in simple_modes:
			check_for_error(${mode}_start(self.idx, iv, key, len(key), 0, <symmetric_${mode}*>&self.state))
			
			% elif mode == 'lrw':
			tweak = kwargs.get('tweak')
			if not isinstance(tweak, basestring) or len(tweak) != 16:
				raise Error('tweak must be 16 byte string')
			check_for_error(${mode}_start(self.idx, iv, key, len(key), tweak, 0, <symmetric_${mode}*>&self.state))
			
			% elif mode == 'f8':
			salt_key = kwargs.get('salt_key')
			if not isinstance(salt_key, basestring):
				raise Error('salt_key must be a string')
			check_for_error(${mode}_start(self.idx, iv, key, len(key), salt_key, len(salt_key), 0, <symmetric_${mode}*>&self.state))
			
			% else:
			raise Error('no start for mode %r' % ${repr(mode)})
			
			% endif
		% endfor
	##
	cpdef get_iv(self):
		if all_getiv[self.mode_i] == NULL:
			raise Error('%r mode does not use an IV' % self.mode)
		cdef unsigned long length
		length = self.desc.block_size
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
no_iv_modes = ${repr(set(no_iv_modes))}
iv_modes = ${repr(set(iv_modes))}


% for mode, i in mode_items:
def ${mode}(key, *args, **kwargs):
	"""Cipher constructor for ${mode.upper()} mode."""
	return Cipher(key, *args, mode=${repr(mode)}, **kwargs)
% endfor


ciphers = []
% for name in ciphers:
try:
	${name} = Descriptor('${name}')
	ciphers.append(${repr(name)})
except ValueError:
	pass
% endfor	
ciphers = tuple(ciphers)
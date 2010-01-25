

class Error(Exception):
	def __init__(self, err):
		if isinstance(err, int):
			Exception.__init__(self, error_to_string(err))
		else:
			Exception.__init__(self, err)


cdef inline check_for_error(int res):
	if res != CRYPT_OK:
		raise Error(res)



def test_cipher():
	"""Run the internal tests."""
	cdef int res
	register_all_ciphers()
	% for name in cipher_names:
	check_for_error(${name}_test())
	% endfor
		

cdef int max_cipher_idx = -1
cpdef int get_cipher_idx(object input):
	global max_cipher_idx
	idx = -1
	if isinstance(input, int):
		idx = input
	elif isinstance(input, basestring):
		idx = find_cipher(input)
		if idx == -1:
			% for i, name in enumerate(cipher_names):
			${'el' if i else ''}if input == ${repr(name)}:
				idx = register_cipher(&${name}_desc)
			% endfor	
			max_cipher_idx = max(idx, max_cipher_idx)
	elif isinstance(input, CipherDescriptor):
		idx = input.idx
	if idx < 0 or idx > max_cipher_idx:
		raise ValueError('could not find cipher %r' % input)
	return idx

cpdef register_all_ciphers():
	global max_cipher_idx
	% for name in cipher_names:
	max_cipher_idx = max(max_cipher_idx, register_cipher(&${name}_desc))
	% endfor
	
cdef class CipherDescriptor(object):
	
	cdef readonly int idx
	cdef cipher_desc desc
	
	def __init__(self, cipher):
		self.idx = get_cipher_idx(cipher)
		self.desc = cipher_descriptors[self.idx]
	
	% for name in cipher_properties:
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
cdef all_${name}_pt all_${name}[${len(cipher_modes)}]
% endfor

# Define a inline wrapper function for each that properly casts the symmetric
# state to the right type. Then set these wrappers into the arrays.
% for mode, i in cipher_mode_items:
% for type in 'encrypt', 'decrypt':
cdef inline int null_${mode}_${type}(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return ${mode}_${type}(input, out, length, <symmetric_${mode}*>state)
all_${type}[${i}] = null_${mode}_${type}
% endfor
% if mode in cipher_iv_modes:
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
	% for mode in cipher_modes:
	symmetric_${mode} ${mode}
	% endfor


cdef class Cipher(CipherDescriptor):
	
	cdef symmetric_all state
	cdef object _mode
	cdef int mode_i
	
	def __init__(self, key, iv=None, cipher='aes', mode='ecb', **kwargs):
		self._mode = str(mode).lower()
		## We must keep these indices as magic numbers in the source.
		self.mode_i = {
		% for mode, i in cipher_mode_items:
			${repr(mode)}: ${i},
		% endfor
		}.get(self._mode, -1)
		if self.mode_i < 0:
			raise Error('no mode %r' % mode)
		CipherDescriptor.__init__(self, cipher)
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
		
		% for mode, i in cipher_mode_items:
		${'el' if i else ''}if self.mode_i == ${i}:
			% if mode == 'ecb':
			check_for_error(ecb_start(self.idx, key, len(key), 0, <symmetric_${mode}*>&self.state))
			
			% elif mode == 'ctr':
			check_for_error(ctr_start(self.idx, iv, key, len(key), 0, CTR_COUNTER_BIG_ENDIAN, <symmetric_${mode}*>&self.state))
			
			% elif mode in cipher_simple_modes:
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
modes = ${repr(tuple(mode for mode, i in cipher_mode_items))}
simple_modes = ${repr(set(cipher_simple_modes))}
no_iv_modes = ${repr(set(cipher_no_iv_modes))}
iv_modes = ${repr(set(cipher_iv_modes))}





cipher_descs = {}
% for name in cipher_names:
try:
	cipher_descs[${repr(name)}] = CipherDescriptor(${repr(name)})
except ValueError:
	pass
% endfor

cipher_modes = {}
% for mode, i in cipher_mode_items:
def ${mode}(key, *args, **kwargs):
	"""Cipher constructor for ${mode.upper()} mode."""
	return Cipher(key, *args, mode=${repr(mode)}, **kwargs)
cipher_modes[${repr(mode)}] = ${mode}
% endfor












def test_hash():
	"""Run the internal tests."""
	register_all_hashes()
	% for name in hash_names:
	check_for_error(${name}_desc.test())
	% endfor


cdef int max_hash_idx = -1
cpdef int get_hash_idx(object input):
	global max_hash_idx
	idx = -1
	if isinstance(input, int):
		idx = input
	elif isinstance(input, basestring):
		idx = find_hash(input)
		if idx == -1:
			% for i, name in enumerate(hash_names):
			${'el' if i else ''}if input == ${repr(name)}:
				idx = register_hash(&${name}_desc)
			% endfor	
			max_hash_idx = max(idx, max_hash_idx)
	elif isinstance(input, HashDescriptor):
		idx = input.idx
	if idx < 0 or idx > max_hash_idx:
		raise ValueError('could not find hash %r' % input)
	return idx
	
	
cpdef register_all_hashes():
	global max_hash_idx
	% for name in hash_names:
	max_hash_idx = max(max_hash_idx, register_hash(&${name}_desc))
	% endfor


cdef class HashDescriptor(object):
	
	cdef int idx
	cdef hash_desc desc
	
	def __init__(self, hash):
		self.idx = get_hash_idx(hash)
		self.desc = hash_descriptors[self.idx]

	% for name in hash_properties:
	@property
	def ${name}(self):
		return self.desc.${name}

	% endfor
	##
	def __repr__(self):
		return ${repr('<%s.%s of %s>')} % (
			self.__class__.__module__, self.__class__.__name__, self.desc.name)
	
	def __call__(self, *args):
		return Hash(self.desc.name, *args)

			
cdef class Hash(HashDescriptor):
	
	cdef hash_state state
	
	def __init__(self, hash, *args):
		HashDescriptor.__init__(self, hash)
		self.init()
		for arg in args:
			self.update(arg)
	
	def __repr__(self):
		return ${repr('<%s.%s of %s at 0x%x>')} % (
			self.__class__.__module__, self.__class__.__name__, self.name,
			id(self))
	
	cpdef init(self):
		self.desc.init(&self.state)

	cpdef update(self, input):
		check_for_error(self.desc.process(&self.state, input, len(input)))
	
	cpdef digest(self):
		cdef hash_state state
		memcpy(&state, &self.state, sizeof(hash_state))
		out = PyString_FromStringAndSize(NULL, self.desc.digest_size)
		check_for_error(self.desc.done(&state, out))
		return out
	
	def hexdigest(self, *args):
		return self.digest(*args).encode('hex')
	
	cpdef copy(self):
		cdef Hash copy = self.__class__(self.desc.name)
		memcpy(&copy.state, &self.state, sizeof(hash_state))
		return copy
	

hash_descs = {}
% for hash in hash_names:
try:
	hash_descs[${repr(hash)}] = HashDescriptor(${repr(hash)})
except ValueError:
	pass
% endfor










def test_mac():
	register_all_hashes()
	check_for_error(hmac_test());

			
cdef class hmac(HashDescriptor):
	
	cdef hmac_state state
	
	def __init__(self, hash, key, *args):
		HashDescriptor.__init__(self, hash)
		self.init(key)
		for arg in args:
			self.update(arg)
	
	def __repr__(self):
		return ${repr('<%s.%s of %s at 0x%x>')} % (
			self.__class__.__module__, self.__class__.__name__, self.name,
			id(self))
	
	cpdef init(self, key):
		hmac_init(&self.state, self.idx, key, len(key))
	
	cpdef update(self, input):
		check_for_error(hmac_process(&self.state, input, len(input)))
	
	
	cpdef digest(self, length=None):
		if length is None:
			length = self.desc.digest_size
		cdef unsigned long c_len = length
		cdef hmac_state state
		memcpy(&state, &self.state, sizeof(hash_state))
		out = PyString_FromStringAndSize(NULL, self.desc.digest_size)
		check_for_error(hmac_done(&state, out, &c_len))
		return out[:c_len]
	
	def hexdigest(self, *args):
		return self.digest(*args).encode('hex')
	
	cpdef copy(self):
		cdef hmac copy = self.__class__(self.desc.name)
		memcpy(&copy.state, &self.state, sizeof(hmac_state))
		return copy





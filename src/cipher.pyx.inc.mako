
def test_cipher():
	"""Run internal cipher tests."""
	cdef int res
	register_all_ciphers()
	% for name in cipher_names:
	% if not name.endswith('_enc'):
	check_for_error(${name}_test())
	% endif
	% endfor
		

cdef int max_cipher_idx = -1
def get_cipher_idx(input):
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
		raise Error('could not find cipher %r' % input)
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
		
	def __repr__(self):
		return ${repr('<%s.%s of %s>')} % (
			self.__class__.__module__, self.__class__.__name__, self.desc.name)
				
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
	

# Define function pointer types for each of the functions that have common
# signatures, except they take a null pointer to the symmetric state.
ctypedef int (*cipher_crypt_pt)(unsigned char *, unsigned char *, unsigned long, void *)
ctypedef cipher_crypt_pt cipher_encrypt_pt
ctypedef cipher_crypt_pt cipher_decrypt_pt
ctypedef int (*cipher_getiv_pt)(unsigned char *, unsigned long *, void *)
ctypedef int (*cipher_setiv_pt)(unsigned char *, unsigned long  , void *)
ctypedef int (*cipher_done_pt)(void *)

# Setup arrays to hold the all the function pointers.
% for name in 'encrypt decrypt getiv setiv done'.split():
cdef cipher_${name}_pt cipher_${name}[${len(cipher_modes)}]
% endfor

# Define a inline wrapper function for each that properly casts the symmetric
# state to the right type. Then set these wrappers into the arrays.
% for mode, i in cipher_mode_items:
% for type in 'encrypt', 'decrypt':
cdef inline int wrapped_${mode}_${type}(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return ${mode}_${type}(input, out, length, <symmetric_${mode}*>state)
cipher_${type}[${i}] = wrapped_${mode}_${type}
% endfor
% if mode in cipher_iv_modes:
cdef inline int wrapped_${mode}_getiv(unsigned char *output, unsigned long *outlen, void *state):
	return ${mode}_getiv(output, outlen, <symmetric_${mode}*>state)
cipher_getiv[${i}] = wrapped_${mode}_getiv
cdef inline int wrapped_${mode}_setiv(unsigned char *input, unsigned long inlen, void *state):
	return ${mode}_setiv(input, inlen, <symmetric_${mode}*>state)
cipher_setiv[${i}] = wrapped_${mode}_setiv
% endif
cdef inline int wrapped_${mode}_done(void *state):
	return ${mode}_done(<symmetric_${mode}*>state)
cipher_done[${i}] = wrapped_${mode}_done
% endfor


# Define a type to masquarade as ANY of the mode states.
cdef union symmetric_all:
	% for mode in cipher_modes:
	symmetric_${mode} ${mode}
	% endfor


cdef class Cipher(CipherDescriptor):
	
	cdef symmetric_all state
	cdef readonly object mode
	cdef int mode_i
	
	def __init__(self, key, iv=None, cipher='aes', mode='ecb', **kwargs):
		self.mode = mode
		## We must keep these indices as magic numbers in the source.
		self.mode_i = {
		% for mode, i in cipher_mode_items:
			${repr(mode)}: ${i},
		% endfor
		}.get(self.mode, -1)
		if self.mode_i < 0:
			raise Error('no mode %r' % mode)
		CipherDescriptor.__init__(self, cipher)
		self.start(key, iv, **kwargs)
	
	def __repr__(self):
		return ${repr('<%s.%s with %s in %s mode at 0x%x>')} % (
			self.__class__.__module__, self.__class__.__name__, self.name,
			self.mode, id(self))
	
	def start(self, key, iv=None, **kwargs):
		# Both the key and the iv are "const" for the start functions, so we
		# don't need to worry about making unique ones.
		
		if iv is None:
			iv = '\0' * self.desc.block_size
		if not isinstance(iv, basestring) or len(iv) != self.desc.block_size:
			raise Error('iv must be %d bytes' % self.desc.block_size)
		
		% for mode, i in cipher_mode_items:
		${'el' if i else ''}if self.mode_i == ${i}: # ${mode}
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
		if cipher_getiv[self.mode_i] == NULL:
			raise Error('%r mode does not use an IV' % self.mode)
		cdef unsigned long length
		length = self.desc.block_size
		iv = PyString_FromStringAndSize(NULL, length)
		check_for_error(cipher_getiv[self.mode_i](iv, &length, &self.state))
		return iv
	
	cpdef set_iv(self, iv):	
		if cipher_getiv[self.mode_i] == NULL:
			raise Error('%r mode does not use an IV' % self.mode)
		check_for_error(cipher_setiv[self.mode_i](iv, len(iv), &self.state))
	
	% for type in 'encrypt decrypt'.split():
	cpdef ${type}(self, input):
		"""${type.capitalize()} a string."""
		cdef int length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		check_for_error(cipher_${type}[self.mode_i](input, output, length, &self.state))
		return output
	
	% endfor


cipher_names = ${repr(set(cipher_names))}
cipher_modes = ${repr(set(cipher_modes.keys()))}



from common cimport *
from common import Error

# Register all of the ciphers.
# We don't really need to worry about doing this as they are needed as this
# doesn't take very long at all.
cdef int max_cipher_idx = -1
% for name in cipher_names:
max_cipher_idx = max(max_cipher_idx, register_cipher(&${name}_desc))
% endfor


def test():
	"""Run the internal tests."""
	cdef int res
	% for name in cipher_names:
	check_for_error(${name}_test())
	% endfor
		

def get_idx(input):	
	idx = -1
	if isinstance(input, int):
		idx = input
	elif hasattr(input, 'idx'):
		idx = input.idx
	else:
		idx = find_cipher(input)
	if idx < 0 or idx > max_cipher_idx:
		raise ValueError('could not find cipher %r' % input)
	return idx

	
cdef class Descriptor(object):
	
	cdef readonly int idx
	cdef cipher_desc desc
	
	def __init__(self, cipher):
		self.idx = get_idx(cipher)
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


cdef class Cipher(Descriptor):
	
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


% for mode, i in cipher_mode_items:
def ${mode}(key, *args, **kwargs):
	"""Cipher constructor for ${mode.upper()} mode."""
	return Cipher(key, *args, mode=${repr(mode)}, **kwargs)
% endfor


ciphers = []
% for name in cipher_names:
try:
	${name} = Descriptor('${name}')
	ciphers.append(${repr(name)})
except ValueError:
	pass
% endfor	
ciphers = tuple(ciphers)
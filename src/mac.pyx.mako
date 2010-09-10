
from tomcrypt._core cimport *
from tomcrypt._core import Error
from tomcrypt.cipher cimport Descriptor as CipherDescriptor
from tomcrypt.cipher import get_cipher_idx
from tomcrypt.hash cimport Descriptor as HashDescriptor
from tomcrypt.hash import get_hash_idx


def test_library():
	"""Run internal libtomcrypt mac tests."""
	% for mac in mac_names:
	check_for_error(${mac}_test())
	% endfor


# A data type to hold ALL of the different mac type states.
cdef union mac_state:
	% for mac in mac_names:
	${mac}_state ${mac}
	% endfor
	

	
# Define function pointer types for each of the functions that have common
# signatures, except they take a null pointer to the symmetric state.
ctypedef int (*mac_init_pt)(mac_state *, int, unsigned char *, unsigned long)
ctypedef int (*mac_process_pt)(mac_state *, unsigned char *, unsigned long)
ctypedef int (*mac_done_pt)(mac_state *, unsigned char *, unsigned long *)

# Setup arrays to hold the all the function pointers.
% for name in 'init process done'.split():
cdef mac_${name}_pt mac_${name}[${len(mac_names)}]
% endfor

# Define a inline wrapper function for each that properly casts the symmetric
# state to the right type. Then set these wrappers into the arrays.
% for mac, i in mac_items:
cdef inline int wrapped_${mac}_init(mac_state * state, int idx, unsigned char * key, unsigned long keylen):
	return ${mac}_init(<${mac}_state *> state, idx, key, keylen)
mac_init[${i}] = wrapped_${mac}_init
cdef inline int wrapped_${mac}_process(mac_state * state, unsigned char * key, unsigned long keylen):
	return ${mac}_process(<${mac}_state *> state, key, keylen)
mac_process[${i}] = wrapped_${mac}_process
cdef inline int wrapped_${mac}_done(mac_state * state, unsigned char * key, unsigned long *keylen):
	return ${mac}_done(<${mac}_state *> state, key, keylen)
mac_done[${i}] = wrapped_${mac}_done
% endfor


hash_macs = ${repr(hash_macs)}
cipher_macs = ${repr(cipher_macs)}
mac_names = ${repr(set(mac_names))}


cdef class MAC(object):
	
	cdef readonly object mode
	cdef int mode_i
	cdef readonly bint uses_hash
	cdef readonly bint uses_cipher
	
	cdef readonly object desc
	
	cdef mac_state state
	cdef object key
	
	def __init__(self, mode, idx, key, input=''):
		self.mode = mode
		% for mac, i in mac_items:
		${'el' if i else ''}if mode == ${repr(mac)}:
			self.mode_i = ${i}
		% endfor
		else:
			raise Error('no MAC mode %r' % mode)
		
		self.uses_hash = self.mode in ${repr(hash_macs)}
		self.uses_cipher = not self.uses_hash
		
		if self.uses_hash:
			self.desc = HashDescriptor(idx)
		else:
			self.desc = CipherDescriptor(idx)
		
		self.key = key
		check_for_error(mac_init[self.mode_i](&self.state, self.desc.idx, key, len(key)))
		self.update(input)
	
	def __dealloc__(self):
		if self.mode_i == ${mac_ids['hmac']}:
			free(self.state.hmac.key)
	
	def __repr__(self):
		return ${repr('<%s.%s of %s using %s at 0x%x>')} % (
			self.__class__.__module__, self.__class__.__name__, self.mode,
			self.desc.name, id(self))
	
	cpdef update(self, str input):
		check_for_error(mac_process[self.mode_i](&self.state, input, len(input)))
	
	cpdef digest(self, length=None):
		if length is None:
			if self.uses_hash:
				length = self.desc.digest_size
			else:
				length = self.desc.block_size
		cdef unsigned long c_length = length
		
		# Make a copy of the hmac state and all of it's parts. We need to do
		# this because the *_done function mutates the state. The key is
		# deallocated so we aren't causing a memory leak here.
		cdef mac_state state
		memcpy(&state, &self.state, sizeof(mac_state))
		
		if self.mode_i == ${mac_ids['hmac']}:
			state.hmac.key = <unsigned char *>malloc(self.desc.block_size)
			memcpy(state.hmac.key, self.state.hmac.key, self.desc.block_size)
		
		out = PyString_FromStringAndSize(NULL, c_length)
		check_for_error(mac_done[self.mode_i](&state, out, &c_length))
		return out[:c_length]
	
	cpdef hexdigest(self, length=None):
		return self.digest(length).encode('hex')
	
	cpdef copy(self):
		cdef MAC copy = self.__class__(self.mode, self.desc, self.key)
		memcpy(&copy.state, &self.state, sizeof(mac_state))
		
		if self.mode_i == ${mac_ids['hmac']}:
			copy.state.hmac.key = <unsigned char *>malloc(self.desc.block_size)
			memcpy(copy.state.hmac.key, self.state.hmac.key, self.desc.block_size)
		
		return copy

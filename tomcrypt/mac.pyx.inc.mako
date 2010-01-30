
def test_mac():
	get_hash_idx('md5')
	get_hash_idx('sha1')
	get_cipher_idx('aes')
	% for mac in mac_names:
	check_for_error(${mac}_test())
	% endfor


# A data type to hold ALL of the different mac type states.
cdef union mac_all_state:
	% for mac in mac_names:
	${mac}_state ${mac}
	% endfor
	

	
# Define function pointer types for each of the functions that have common
# signatures, except they take a null pointer to the symmetric state.
ctypedef int (*mac_init_pt)(void *, int, unsigned char *, unsigned long)
ctypedef int (*mac_process_pt)(void *, unsigned char *, unsigned long)
ctypedef int (*mac_done_pt)(void *, unsigned char *, unsigned long *)

# Setup arrays to hold the all the function pointers.
% for name in 'init process done'.split():
cdef mac_${name}_pt mac_${name}[${len(mac_names)}]
% endfor

# Define a inline wrapper function for each that properly casts the symmetric
# state to the right type. Then set these wrappers into the arrays.
% for mac, i in mac_ids:
cdef inline int wrapped_${mac}_init(void * state, int idx, unsigned char * key, unsigned long keylen):
	return ${mac}_init(<${mac}_state *> state, idx, key, keylen)
mac_init[${i}] = wrapped_${mac}_init
cdef inline int wrapped_${mac}_process(void * state, unsigned char * key, unsigned long keylen):
	return ${mac}_process(<${mac}_state *> state, key, keylen)
mac_process[${i}] = wrapped_${mac}_process
cdef inline int wrapped_${mac}_done(void * state, unsigned char * key, unsigned long *keylen):
	return ${mac}_done(<${mac}_state *> state, key, keylen)
mac_done[${i}] = wrapped_${mac}_done
% endfor


cdef class hmac(HashDescriptor):
	
	cdef hmac_state state
	cdef object key
	
	def __init__(self, key, hash, input=''):
		HashDescriptor.__init__(self, hash)
		check_for_error(hmac_init(&self.state, self.idx, key, len(key)))
		self.key = key
		self.update(input)
	
	def __dealloc__(self):
		free(self.state.key)
	
	def __repr__(self):
		return ${repr('<%s.%s of %s at 0x%x>')} % (
			self.__class__.__module__, self.__class__.__name__, self.name,
			id(self))
	
	cpdef update(self, str input):
		check_for_error(hmac_process(&self.state, input, len(input)))
	
	cpdef digest(self, length=None):
		if length is None:
			length = self.desc.digest_size
		cdef unsigned long c_length = length
		
		# Make a copy of the hmac state and all of it's parts. We need to do
		# this because the *_done function mutates the state. The key is
		# deallocated so we aren't causing a memory leak here.
		cdef hmac_state state
		memcpy(&state, &self.state, sizeof(hmac_state))
		state.key = <unsigned char *>malloc(self.desc.block_size)
		memcpy(state.key, self.state.key, self.desc.block_size)
		
		out = PyString_FromStringAndSize(NULL, c_length)
		check_for_error(hmac_done(&state, out, &c_length))
		return out[:c_length]
	
	cpdef hexdigest(self, length=None):
		return self.digest(length).encode('hex')
	
	cpdef copy(self):
		cdef hmac copy = self.__class__(self.key, self.idx)
		memcpy(&copy.state, &self.state, sizeof(hmac_state))
		copy.state.key = <unsigned char *>malloc(self.desc.block_size)
		memcpy(copy.state.key, self.state.key, self.desc.block_size)
		return copy

def test_mac():
	register_all_hashes()
	check_for_error(hmac_test());

			
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

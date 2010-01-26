def test_mac():
	register_all_hashes()
	check_for_error(hmac_test());

			
cdef class hmac(HashDescriptor):
	
	cdef hmac_state state
	
	def __init__(self, key, hash, *args):
		HashDescriptor.__init__(self, hash)
		check_for_error(hmac_init(&self.state, self.idx, key, len(key)))
		for arg in args:
			self.update(arg)
	
	def __repr__(self):
		return ${repr('<%s.%s of %s at 0x%x>')} % (
			self.__class__.__module__, self.__class__.__name__, self.name,
			id(self))
	
	cpdef update(self, str input):
		check_for_error(hmac_process(&self.state, input, len(input)))
	
	cpdef digest(self, length=None):
		if length is None:
			length = self.desc.digest_size
		cdef unsigned long c_len = length
		
		# Make a copy of the hmac state and all of it's parts. We need to do
		# this because the *_done function deallocates a bunch of memory.
		cdef hmac_state state
		memcpy(&state, &self.state, sizeof(hmac_state))
		state.key = <unsigned char *>malloc(self.desc.block_size)
		memcpy(state.key, self.state.key, self.desc.block_size)
		
		out = PyString_FromStringAndSize(NULL, c_len)
		check_for_error(hmac_done(&state, out, &c_len))
		return out[:c_len]
	
	def hexdigest(self, *args):
		return self.digest(*args).encode('hex')
	
	cpdef copy(self):
		cdef hmac copy = self.__class__(self.desc.name)
		memcpy(&copy.state, &self.state, sizeof(hmac_state))
		return copy

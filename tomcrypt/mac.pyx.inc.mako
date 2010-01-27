def test_mac():
	register_all_hashes()
	check_for_error(hmac_test());



# Attempt to make my own descriptor!

cdef hash_desc py_desc

cdef void py_hash_init(hash_state *state):
	print 'init'
	pass

cdef int py_hash_process(hash_state *state, unsigned char *input, unsigned long inputlen):
	print 'process', PyString_FromStringAndSize(<char *>input, inputlen)
	return CRYPT_OK

cdef int py_hash_done(hash_state *state, unsigned char *out):
	print 'done'
	out = "hellothere"
	return CRYPT_OK

cdef int py_hash_test():
	return CRYPT_OK

py_desc.name = "python"
py_desc.block_size = 10
py_desc.digest_size = 10
py_desc.init = py_hash_init
py_desc.process = py_hash_process
py_desc.done = py_hash_done
py_desc.test = py_hash_test

cdef int py_desc_idx = register_hash(&py_desc)

cdef struct py_state:
	object obj

	
cdef class hmac(HashDescriptor):
	
	cdef hmac_state state
	cdef object key
	
	def __init__(self, key, hash, input=''):
		cdef py_state *state
		if not isinstance(hash, HashDescriptor) and hasattr(hash, 'call'):
			state = <py_state *> malloc(sizeof(py_state))
			state.obj = hash
			state.obj = hash
			self.state.md.data = <void *> state
			self.state.hashstate.data = <void *> state
			hash = py_desc_idx
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




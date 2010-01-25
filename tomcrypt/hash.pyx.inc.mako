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
		# This does not return an error value, so we don't check.
		self.desc.init(&self.state)
		for arg in args:
			self.update(arg)
	
	def __repr__(self):
		return ${repr('<%s.%s of %s at 0x%x>')} % (
			self.__class__.__module__, self.__class__.__name__, self.name,
			id(self))		

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

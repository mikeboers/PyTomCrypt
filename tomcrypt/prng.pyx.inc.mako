

cdef int max_prng_idx = -1
def get_prng_idx(input):
	global max_prng_idx
	idx = -1
	if isinstance(input, int):
		idx = input
	elif isinstance(input, basestring):
		idx = find_prng(input)
		if idx == -1:
			% for i, name in enumerate(prng_names):
			${'el' if i else ''}if input == ${repr(name)}:
				idx = register_prng(&${name}_desc)
			% endfor	
			max_prng_idx = max(idx, max_prng_idx)
	# elif isinstance(input, HashDescriptor):
	# 	idx = input.idx
	if idx < 0 or idx > max_prng_idx:
		raise ValueError('could not find prng %r' % input)
	return idx

cpdef register_all_prngs():
	global max_prng_idx
	% for name in prng_names:
	max_prng_idx = max(max_prng_idx, register_prng(&${name}_desc))
	% endfor

def test_prng():
	"""Run the internal tests."""
	print 'registering'
	register_all_prngs()
	% for name in prng_names:
	print ${repr(name)}
	check_for_error(${name}_desc.test())
	% endfor


prng_names = ${repr(set(prng_names))}


cdef class PRNG(object):
	
	cdef prng_desc desc
	cdef readonly int idx
	cdef prng_state state
	
	def __init__(self, prng, int auto_seed=0):
		self.idx = get_prng_idx(prng)
		self.desc = prng_descriptors[self.idx]
		self.start()
		if auto_seed > 0:
			self.auto_seed(auto_seed)
	
	cpdef auto_seed(self, int bits):
		check_for_error(rng_make_prng(bits, self.idx, &self.state, NULL))
	
	def __dealloc__(self):
		self.desc.done(&self.state)
	
	cpdef start(self):
		check_for_error(self.desc.start(&self.state))
	
	cpdef add_entropy(self, input):
		check_for_error(self.desc.add_entropy(input, len(input), &self.state))
	
	cpdef ready(self):
		check_for_error(self.desc.ready(&self.state))
	
	cpdef read(self, int length):
		out = PyString_FromStringAndSize(NULL, length)
		cdef unsigned long len_read = self.desc.read(out, length, &self.state)
		return out[:len_read]
	
	cpdef get_state(self):
		pass
	
	cpdef set_state(self, input):
		pass
	
	
		

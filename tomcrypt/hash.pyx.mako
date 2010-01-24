

from tomcrypt.common cimport *
from tomcrypt.common import Error


% if hash_do_hash:
def test():
	"""Run the internal tests."""
	% for name in hash_names:
	check_for_error(${name}_desc.test())
	% endfor
% else:
def test():
	check_for_error(hmac_test());
% endif


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
	elif isinstance(input, Descriptor):
		idx = input.idx
	if idx < 0 or idx > max_hash_idx:
		raise ValueError('could not find hash %r' % input)
	return idx


cdef class Descriptor(object):

	cdef readonly int idx
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
		return ${hash_class_name}(self.desc.name, *args)

			
cdef class ${hash_class_name}(Descriptor):
	
	cdef ${hash_type}_state state
	
	% if hash_do_hash:
	def __init__(self, hash, *args):
	% else:
	def __init__(self, hash, key, *args):
	% endif
		Descriptor.__init__(self, hash)
		% if hash_do_hash:
		self.init()
		% else:
		self.init(key)
		% endif
		for arg in args:
			self.update(arg)
	
	def __repr__(self):
		return ${repr('<%s.%s of %s at 0x%x>')} % (
			self.__class__.__module__, self.__class__.__name__, self.name,
			id(self))
	
	% if hash_do_hash:
	cpdef init(self):
		self.desc.init(&self.state)
	% else:
	cpdef init(self, key):
		hmac_init(&self.state, self.idx, key, len(key))
	% endif
	
	<%
	func_prefix = 'self.desc.' if hash_do_hash else 'hmac_'
	%>
	##
	cpdef update(self, input):
		check_for_error(${func_prefix}process(&self.state, input, len(input)))
	
	% if hash_do_hash:
	cpdef digest(self):
	% else:
	cpdef digest(self, length=None):
		if length is None:
			length = self.desc.digest_size
		cdef unsigned long c_len = length
	% endif
		cdef ${hash_type}_state state
		memcpy(&state, &self.state, sizeof(hash_state))
		out = PyString_FromStringAndSize(NULL, self.desc.digest_size)
		% if hash_do_hash:
		check_for_error(${func_prefix}done(&state, out))
		return out
		% else:
		check_for_error(${func_prefix}done(&state, out, &c_len))
		return out[:c_len]
		% endif
	
	def hexdigest(self, *args):
		return self.digest(*args).encode('hex')
	
	cpdef copy(self):
		cdef ${hash_class_name} copy = self.__class__(self.desc.name)
		memcpy(&copy.state, &self.state, sizeof(${hash_type}_state))
		return copy
	
	
# To match the hashlib/hmac API.	
new = ${hash_class_name}

hashes = []
% for hash in hash_names:
try:
	${hash} = Descriptor(${repr(hash)})
	hashes.append(${repr(hash)})
except ValueError:
	pass
% endfor
hashes = tuple(hashes)





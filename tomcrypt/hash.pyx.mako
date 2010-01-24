

from common cimport *
from tomcrypt.common import Error


cdef extern from "tomcrypt.h":
	
	cdef union hash_state "Hash_state":
		pass
	
	cdef struct hmac_state "Hmac_state":
		pass
	
	# Hash descriptor.
	cdef struct hash_desc "ltc_hash_descriptor":
		char * name
		unsigned long digest_size "hashsize"
		unsigned long block_size "blocksize"
		void init(hash_state *md)
		int process(hash_state *md, unsigned char *input, unsigned long inputlen)
		int done(hash_state *md, unsigned char *out)
		int test()
	
	# The array which contains the descriptors once setup.
	hash_desc hash_descriptors "hash_descriptor" []
	
	##% for name in hashes:
	##void ${name}_init(hash_state *md)
	##int ${name}_process(hash_state *md, unsigned char *input, unsigned long inputlen)
	##int ${name}_done(hash_state *md, unsigned char *out)
	##% endfor
	
	# The descriptors themselves.
	% for name in hash_names:
	hash_desc ${name}_desc
	% endfor
		
	# Functions for registering and finding the registered hashs.
	int register_hash(hash_desc *hash)
	int find_hash(char * name)
	
	% if hash_do_hmac:
	int hmac_test()
	int hmac_init(hmac_state *, int, unsigned char *, unsigned long)
	int hmac_process(hmac_state *, unsigned char *, unsigned long)
	int hmac_done(hmac_state *, unsigned char *, unsigned long *)
	% endif


cdef int max_hash_idx = -1
% for name in hash_names:
max_hash_idx = max(max_hash_idx, register_hash(&${name}_desc))
% endfor

% if hash_do_hash:
def test():
	"""Run the internal tests."""
	cdef int res
	% for name in hash_names:
	check_for_error(${name}_desc.test())
	% endfor
% else:
def test():
	check_for_error(hmac_test());
% endif


def get_idx(input):	
	idx = -1
	if isinstance(input, int):
		idx = input
	elif hasattr(input, 'idx'):
		idx = input.idx
	else:
		idx = find_hash(input)
	if idx < 0 or idx > max_hash_idx:
		raise ValueError('could not find hash %r' % input)
	return idx


cdef class Descriptor(object):

	cdef readonly int idx
	cdef hash_desc desc
	
	def __init__(self, hash):
		self.idx = get_idx(hash)
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





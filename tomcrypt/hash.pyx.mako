
<%!

import os
DO_HMAC = 'PyTomCrypt_do_hmac' in os.environ
DO_HASH = not DO_HMAC
class_name = 'Hash' if DO_HASH else 'HMAC'
type = class_name.lower()

ALL_CIPHERS = False

hashes = '''
md2
md4
md5
rmd128
rmd160
rmd256
rmd320
sha1
sha224
sha256
sha384
sha512
tiger
whirlpool

'''.strip().split()

%>


include "common.pxi"


cdef extern from "tomcrypt.h":
	
	cdef union hash_state "Hash_state":
		char dummy[1]
	
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
	% for name in hashes:
	hash_desc ${name}_desc
	% endfor
		
	# Functions for registering and finding the registered hashs.
	int register_hash(hash_desc *hash)
	int find_hash(char * name)
	
	% if DO_HMAC:
	int hmac_test()
	int hmac_init(hmac_state *, int, unsigned char *, unsigned long)
	int hmac_process(hmac_state *, unsigned char *, unsigned long)
	int hmac_done(hmac_state *, unsigned char *, unsigned long *)
	% endif


cdef int max_hash_idx = -1
% for name in hashes:
max_hash_idx = max(max_hash_idx, register_hash(&${name}_desc))
% endfor

% if DO_HASH:
def test():
	"""Run the internal tests."""
	cdef int res
	% for name in hashes:
	check_for_error(${name}_desc.test())
	% endfor
% else:
def test():
	check_for_error(hmac_test());
% endif


cdef class Descriptor(object):

	cdef int idx
	cdef hash_desc desc
	
	def __init__(self, hash):
		if isinstance(hash, int):
			self.idx = hash
		elif hasattr(hash, 'hash_idx'):
			self.idx = hash.hash_idx
		else:
			self.idx = find_hash(hash)
		if self.idx < 0 or self.idx > max_hash_idx:
			raise ValueError('could not find hash %r' % hash)
		self.desc = hash_descriptors[self.idx]
	
	@property
	def hash_idx(self):
		return self.idx

	% for name in 'name', 'digest_size', 'block_size':
	@property
	def ${name}(self):
		return self.desc.${name}

	% endfor
	##
	
	def __repr__(self):
		return ${repr('<%s.%s of %s>')} % (
			self.__class__.__module__, self.__class__.__name__, self.desc.name)
	
	def __call__(self, *args):
		return ${class_name}(self.desc.name, *args)

			
cdef class ${class_name}(Descriptor):
	
	cdef ${type}_state state
	
	% if DO_HASH:
	def __init__(self, hash, *args):
	% else:
	def __init__(self, hash, key, *args):
	% endif
		Descriptor.__init__(self, hash)
		% if DO_HASH:
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
	
	% if DO_HASH:
	cpdef init(self):
		self.desc.init(&self.state)
	% else:
	cpdef init(self, key):
		hmac_init(&self.state, self.idx, key, len(key))
	% endif
	
	<% func_prefix = 'self.desc.' if DO_HASH else 'hmac_' %>
	cpdef update(self, input):
		check_for_error(${func_prefix}process(&self.state, input, len(input)))
	
	# cpdef done(self):
	# 	out = PyString_FromStringAndSize(NULL, self.desc.digest_size)
	# 	% if DO_HASH:
	# 	check_for_error(${func_prefix}done(&self.state, out))
	# 	return out
	# 	% else:
	# 	cdef unsigned long outlen
	# 	check_for_error(${func_prefix}done(&self.state, out, &outlen))
	# 	return out[:outlen]
	# 	% endif
	
	% if DO_HASH:
	cpdef digest(self):
	% else:
	cpdef digest(self, length=None):
		if length is None:
			length = self.desc.digest_size
		cdef unsigned long c_len = length
	% endif
		cdef ${type}_state state
		memcpy(&state, &self.state, sizeof(hash_state))
		out = PyString_FromStringAndSize(NULL, self.desc.digest_size)
		% if DO_HASH:
		check_for_error(${func_prefix}done(&state, out))
		return out
		% else:
		check_for_error(${func_prefix}done(&state, out, &c_len))
		return out[:c_len]
		% endif
	
	def hexdigest(self, *args):
		return self.digest(*args).encode('hex')
	
	cpdef copy(self):
		# This is rather ineligant. Could find a way to do this more directly.
		cdef ${class_name} copy = self.__class__(self.desc.name)
		memcpy(&copy.state, &self.state, sizeof(${type}_state))
		return copy
	
	
# To match the hashlib API.	
new = ${class_name}

hashes = ${repr(hashes)}	
% for hash in hashes:
${hash} = Descriptor(${repr(hash)})
% endfor





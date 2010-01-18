
<%!

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
	
	# cdef struct hash_state:
	#	char dummy[1]
	cdef union hash_state "Hash_state":
		char dummy[1]
	
	# Cipher descriptor.
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
	## int ${name}_test()
	% endfor
		
	# Functions for registering and finding the registered hashs.
	int register_hash(hash_desc *hash)
	int find_hash(char * name)


% for name in hashes:
register_hash(&${name}_desc)
% endfor


def test():
	"""Run the internal tests."""
	cdef int res
	% for name in hashes:
	check_for_error(${name}_desc.test())
	% endfor


cdef class Hash(object):
	
	cdef int idx
	cdef hash_desc desc
	cdef hash_state state
	
	def __init__(self, name):
		self.idx = find_hash(name)
		if self.idx < 0:
			raise ValueError('could not find hash %r' % name)
		self.desc = hash_descriptors[self.idx]
		self.init()
	
	% for name in 'name', 'digest_size', 'block_size':
	@property
	def ${name}(self):
		return self.desc.${name}
	
	% endfor
	##
	def __repr__(self):
		return ${repr('<%s.%s with %s at 0x%x>')} % (
			self.__class__.__module__, self.__class__.__name__, self.name,
			id(self))
	
	cpdef init(self):
		self.desc.init(&self.state)
	
	cpdef update(self, input):
		check_for_error(self.desc.process(&self.state, input, len(input)))
	
	cpdef done(self):
		out = PyString_FromStringAndSize(NULL, self.desc.digest_size)
		check_for_error(self.desc.done(&self.state, out))
		return out
	
	cpdef digest(self):
		cdef hash_state state
		memcpy(&state, &self.state, sizeof(hash_state))
		out = PyString_FromStringAndSize(NULL, self.desc.digest_size)
		check_for_error(self.desc.done(&state, out))
		return out
	
	cpdef hexdigest(self):
		return self.digest().encode('hex')
	
	
# To match the hashlib API.	
new = Hash

hashes = ${repr(hashes)}	
% for hash in hashes:
def ${hash}():
	"""Hash constructor for ${hash.upper()}."""
	return Hash(${repr(hash)})
% endfor





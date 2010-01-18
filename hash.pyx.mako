
<%!

ALL_CIPHERS = False

hashes = '''
md2
md4
md5
rmd128
rmd160
rmd160
rmd160
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
		unsigned long hashsize
		unsigned long blocksize
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
	
	cdef int hash_idx
	cdef hash_desc hash
	cdef hash_state md
	cdef object _name
	
	def __init__(self, hash):
		self.hash_idx = find_hash(hash)
		if self.hash_idx < 0:
			raise ValueError('could not find %r' % hash)
		self._name = str(hash).lower()
		self.hash = hash_descriptors[self.hash_idx]
	
	@property
	def name(self):
		return self._name
	
	def __repr__(self):
		return ${repr('<%s.%s with %s at 0x%x>')} % (
			self.__class__.__module__, self.__class__.__name__, self.name,
			id(self))






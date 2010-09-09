
from tomcrypt._core cimport *
from tomcrypt._core import Error

from tomcrypt.cipher cimport CipherDescriptor
from tomcrypt.cipher import get_cipher_idx

def test_hash():
	"""Run the internal tests."""
	register_all_hashes()
	get_cipher_idx('aes') # Register AES for the CHC hash.
	% for name in hash_names:
	check_for_error(${name}_desc.test())
	% endfor


cdef int max_hash_idx = -1
def get_hash_idx(input):
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
		raise Error('could not find hash %r' % input)
	return idx
	
	
cpdef register_all_hashes():
	global max_hash_idx
	% for name in hash_names:
	max_hash_idx = max(max_hash_idx, register_hash(&${name}_desc))
	% endfor


cdef class HashDescriptor(object):
	
	def __init__(self, hash):
		self.idx = get_hash_idx(hash)
		self.desc = hash_descriptors[self.idx]
		if not isinstance(self, CHC) and self.name == 'chc_hash':
			raise Error('cannot build chc descriptor')

	% for name in hash_properties:
	@property
	def ${name}(self):
		return self.desc.${name}

	% endfor
	##
	def __repr__(self):
		return ${repr('<%s.%s of %s>')} % (
			self.__class__.__module__, self.__class__.__name__, self.desc.name)
	
	def digest(self, input):
		return self(input).digest()
	
	def hexdigest(self, input):
		return self(input).hexdigest()


cdef class Hash(HashDescriptor):
	
	cdef hash_state state
	
	def __init__(self, hash, input=''):
		HashDescriptor.__init__(self, hash)
		# This does not return an error value, so we don't check.
		self.desc.init(&self.state)
		self.update(input)
	
	def __dealloc__(self):
		cdef unsigned char *out = <unsigned char *> malloc(MAXBLOCKSIZE)
		# Not checking for errors in the deallocator...
		self.desc.done(&self.state, out)
		free(out)
		
	def __repr__(self):
		return ${repr('<%s.%s of %s at 0x%x>')} % (
			self.__class__.__module__, self.__class__.__name__, self.name,
			id(self))		

	cpdef update(self, str input):
		check_for_error(self.desc.process(&self.state, input, len(input)))
	
	cpdef digest(self):
		cdef hash_state state
		memcpy(&state, &self.state, sizeof(hash_state))
		out = PyString_FromStringAndSize(NULL, self.desc.digest_size)
		check_for_error(self.desc.done(&state, out))
		return out
	
	cpdef hexdigest(self):
		return self.digest().encode('hex')
	
	cpdef copy(self):
		cdef Hash copy = self.__class__(self.idx)
		memcpy(&copy.state, &self.state, sizeof(hash_state))
		return copy
	

cdef class CHC(Hash):
	
	cdef readonly CipherDescriptor cipher
	
	def __init__(self, cipher, input=''):
		self.cipher = CipherDescriptor(cipher)
		self.assert_chc_cipher()
		Hash.__init__(self, 'chc', input)
	
	def __repr__(self):
		return ${repr('<%s.%s of %s at 0x%x>')} % (
			self.__class__.__module__, self.__class__.__name__, self.cipher.name,
			id(self))
			
	cdef inline assert_chc_cipher(self):
		# This is kinda ugly to do EVERY time, but I haven't been able to get
		# around it. Whoops.
		check_for_error(chc_register(self.cipher.idx))
		self.desc.block_size  = self.cipher.desc.block_size
		self.desc.digest_size = self.cipher.desc.block_size
	
	@property
	def name(self):
		return 'chc'
	
	@property
	def block_size(self):
		return self.cipher.desc.block_size
	
	@property
	def digest_size(self):
		return self.cipher.desc.block_size
	
	cpdef update(self, str input):
		self.assert_chc_cipher()
		Hash.update(self, input)
	
	# This is only different cause it is taking the cipher block size, and
	# making sure the right hash is still registered.
	cpdef digest(self):
		cdef hash_state state
		memcpy(&state, &self.state, sizeof(hash_state))
		out = PyString_FromStringAndSize(NULL, self.cipher.desc.block_size)
		self.assert_chc_cipher()
		check_for_error(self.desc.done(&state, out))
		return out
				

hash_names = ${repr(set(hash_names))}


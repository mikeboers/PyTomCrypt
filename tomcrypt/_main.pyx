

from tomcrypt.common cimport *
from tomcrypt.common import Error


def test_cipher():
	"""Run the internal tests."""
	cdef int res
	register_all_ciphers()
	check_for_error(aes_test())
	check_for_error(blowfish_test())
	check_for_error(des_test())
		

cdef int max_cipher_idx = -1
cpdef int get_cipher_idx(object input):
	global max_cipher_idx
	idx = -1
	if isinstance(input, int):
		idx = input
	elif isinstance(input, basestring):
		idx = find_cipher(input)
		if idx == -1:
			if input == 'aes':
				idx = register_cipher(&aes_desc)
			elif input == 'blowfish':
				idx = register_cipher(&blowfish_desc)
			elif input == 'des':
				idx = register_cipher(&des_desc)
			max_cipher_idx = max(idx, max_cipher_idx)
	elif isinstance(input, CipherDescriptor):
		idx = input.idx
	if idx < 0 or idx > max_cipher_idx:
		raise ValueError('could not find cipher %r' % input)
	return idx

cpdef register_all_ciphers():
	global max_cipher_idx
	max_cipher_idx = max(max_cipher_idx, register_cipher(&aes_desc))
	max_cipher_idx = max(max_cipher_idx, register_cipher(&blowfish_desc))
	max_cipher_idx = max(max_cipher_idx, register_cipher(&des_desc))
	
cdef class CipherDescriptor(object):
	
	cdef readonly int idx
	cdef cipher_desc desc
	
	def __init__(self, cipher):
		self.idx = get_cipher_idx(cipher)
		self.desc = cipher_descriptors[self.idx]
	
	@property
	def name(self):
		return self.desc.name
	
	@property
	def min_key_size(self):
		return self.desc.min_key_size
	
	@property
	def max_key_size(self):
		return self.desc.max_key_size
	
	@property
	def block_size(self):
		return self.desc.block_size
	
	@property
	def default_rounds(self):
		return self.desc.default_rounds
	
	def key_size(self, key_size):
		cdef int out
		out = key_size
		check_for_error(self.desc.key_size(&out))
		return out
	
	def __call__(self, key, *args, **kwargs):
		return Cipher(key, *args, cipher=self.name, **kwargs)
	






# Define function pointer types for each of the functions that have common
# signatures, except they take a null pointer to the symmetric state.
ctypedef int (*all_crypt_pt)(unsigned char *, unsigned char *, unsigned long, void *)
ctypedef all_crypt_pt all_encrypt_pt
ctypedef all_crypt_pt all_decrypt_pt
ctypedef int (*all_getiv_pt)(unsigned char *, unsigned long *, void *)
ctypedef int (*all_setiv_pt)(unsigned char *, unsigned long  , void *)
ctypedef int (*all_done_pt)(void *)

# Setup arrays to hold the all the function pointers.
cdef all_encrypt_pt all_encrypt[7]
cdef all_decrypt_pt all_decrypt[7]
cdef all_getiv_pt all_getiv[7]
cdef all_setiv_pt all_setiv[7]
cdef all_done_pt all_done[7]

# Define a inline wrapper function for each that properly casts the symmetric
# state to the right type. Then set these wrappers into the arrays.
cdef inline int null_ecb_encrypt(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return ecb_encrypt(input, out, length, <symmetric_ecb*>state)
all_encrypt[0] = null_ecb_encrypt
cdef inline int null_ecb_decrypt(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return ecb_decrypt(input, out, length, <symmetric_ecb*>state)
all_decrypt[0] = null_ecb_decrypt
cdef inline int null_ecb_done(void *state):
	return ecb_done(<symmetric_ecb*>state)
all_done[0] = null_ecb_done
cdef inline int null_cbc_encrypt(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return cbc_encrypt(input, out, length, <symmetric_cbc*>state)
all_encrypt[1] = null_cbc_encrypt
cdef inline int null_cbc_decrypt(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return cbc_decrypt(input, out, length, <symmetric_cbc*>state)
all_decrypt[1] = null_cbc_decrypt
cdef inline int null_cbc_getiv(unsigned char *output, unsigned long *outlen, void *state):
	return cbc_getiv(output, outlen, <symmetric_cbc*>state)
cdef inline int null_cbc_setiv(unsigned char *input, unsigned long inlen, void *state):
	return cbc_setiv(input, inlen, <symmetric_cbc*>state)
all_getiv[1] = null_cbc_getiv
all_setiv[1] = null_cbc_setiv
cdef inline int null_cbc_done(void *state):
	return cbc_done(<symmetric_cbc*>state)
all_done[1] = null_cbc_done
cdef inline int null_ctr_encrypt(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return ctr_encrypt(input, out, length, <symmetric_ctr*>state)
all_encrypt[2] = null_ctr_encrypt
cdef inline int null_ctr_decrypt(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return ctr_decrypt(input, out, length, <symmetric_ctr*>state)
all_decrypt[2] = null_ctr_decrypt
cdef inline int null_ctr_getiv(unsigned char *output, unsigned long *outlen, void *state):
	return ctr_getiv(output, outlen, <symmetric_ctr*>state)
cdef inline int null_ctr_setiv(unsigned char *input, unsigned long inlen, void *state):
	return ctr_setiv(input, inlen, <symmetric_ctr*>state)
all_getiv[2] = null_ctr_getiv
all_setiv[2] = null_ctr_setiv
cdef inline int null_ctr_done(void *state):
	return ctr_done(<symmetric_ctr*>state)
all_done[2] = null_ctr_done
cdef inline int null_cfb_encrypt(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return cfb_encrypt(input, out, length, <symmetric_cfb*>state)
all_encrypt[3] = null_cfb_encrypt
cdef inline int null_cfb_decrypt(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return cfb_decrypt(input, out, length, <symmetric_cfb*>state)
all_decrypt[3] = null_cfb_decrypt
cdef inline int null_cfb_getiv(unsigned char *output, unsigned long *outlen, void *state):
	return cfb_getiv(output, outlen, <symmetric_cfb*>state)
cdef inline int null_cfb_setiv(unsigned char *input, unsigned long inlen, void *state):
	return cfb_setiv(input, inlen, <symmetric_cfb*>state)
all_getiv[3] = null_cfb_getiv
all_setiv[3] = null_cfb_setiv
cdef inline int null_cfb_done(void *state):
	return cfb_done(<symmetric_cfb*>state)
all_done[3] = null_cfb_done
cdef inline int null_ofb_encrypt(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return ofb_encrypt(input, out, length, <symmetric_ofb*>state)
all_encrypt[4] = null_ofb_encrypt
cdef inline int null_ofb_decrypt(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return ofb_decrypt(input, out, length, <symmetric_ofb*>state)
all_decrypt[4] = null_ofb_decrypt
cdef inline int null_ofb_getiv(unsigned char *output, unsigned long *outlen, void *state):
	return ofb_getiv(output, outlen, <symmetric_ofb*>state)
cdef inline int null_ofb_setiv(unsigned char *input, unsigned long inlen, void *state):
	return ofb_setiv(input, inlen, <symmetric_ofb*>state)
all_getiv[4] = null_ofb_getiv
all_setiv[4] = null_ofb_setiv
cdef inline int null_ofb_done(void *state):
	return ofb_done(<symmetric_ofb*>state)
all_done[4] = null_ofb_done
cdef inline int null_lrw_encrypt(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return lrw_encrypt(input, out, length, <symmetric_lrw*>state)
all_encrypt[5] = null_lrw_encrypt
cdef inline int null_lrw_decrypt(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return lrw_decrypt(input, out, length, <symmetric_lrw*>state)
all_decrypt[5] = null_lrw_decrypt
cdef inline int null_lrw_getiv(unsigned char *output, unsigned long *outlen, void *state):
	return lrw_getiv(output, outlen, <symmetric_lrw*>state)
cdef inline int null_lrw_setiv(unsigned char *input, unsigned long inlen, void *state):
	return lrw_setiv(input, inlen, <symmetric_lrw*>state)
all_getiv[5] = null_lrw_getiv
all_setiv[5] = null_lrw_setiv
cdef inline int null_lrw_done(void *state):
	return lrw_done(<symmetric_lrw*>state)
all_done[5] = null_lrw_done
cdef inline int null_f8_encrypt(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return f8_encrypt(input, out, length, <symmetric_f8*>state)
all_encrypt[6] = null_f8_encrypt
cdef inline int null_f8_decrypt(unsigned char *input, unsigned char *out, unsigned long length, void *state):
	return f8_decrypt(input, out, length, <symmetric_f8*>state)
all_decrypt[6] = null_f8_decrypt
cdef inline int null_f8_getiv(unsigned char *output, unsigned long *outlen, void *state):
	return f8_getiv(output, outlen, <symmetric_f8*>state)
cdef inline int null_f8_setiv(unsigned char *input, unsigned long inlen, void *state):
	return f8_setiv(input, inlen, <symmetric_f8*>state)
all_getiv[6] = null_f8_getiv
all_setiv[6] = null_f8_setiv
cdef inline int null_f8_done(void *state):
	return f8_done(<symmetric_f8*>state)
all_done[6] = null_f8_done


# Define a type to masquarade as ANY of the mode states.
cdef union symmetric_all:
	symmetric_ofb ofb
	symmetric_cbc cbc
	symmetric_ecb ecb
	symmetric_ctr ctr
	symmetric_f8 f8
	symmetric_cfb cfb
	symmetric_lrw lrw


cdef class Cipher(CipherDescriptor):
	
	cdef symmetric_all state
	cdef object _mode
	cdef int mode_i
	
	def __init__(self, key, iv=None, cipher='aes', mode='ecb', **kwargs):
		self._mode = str(mode).lower()
		self.mode_i = {
			'ecb': 0,
			'cbc': 1,
			'ctr': 2,
			'cfb': 3,
			'ofb': 4,
			'lrw': 5,
			'f8': 6,
		}.get(self._mode, -1)
		if self.mode_i < 0:
			raise Error('no mode %r' % mode)
		CipherDescriptor.__init__(self, cipher)
		self.start(key, iv, **kwargs)
	
	def __repr__(self):
		return '<%s.%s with %s in %s mode at 0x%x>' % (
			self.__class__.__module__, self.__class__.__name__, self.name,
			self.mode, id(self))
	
	@property
	def mode(self):
		return self._mode
	
	def start(self, key, iv=None, **kwargs):
		# Both the key and the iv are "const" for the start functions, so we
		# don't need to worry about making unique ones.
		
		if iv is None:
			iv = '\0' * self.desc.block_size
		if not isinstance(iv, basestring) or len(iv) != self.desc.block_size:
			raise Error('iv must be %d bytes' % self.desc.block_size)
		
		if self.mode_i == 0:
			check_for_error(ecb_start(self.idx, key, len(key), 0, <symmetric_ecb*>&self.state))
			
		elif self.mode_i == 1:
			check_for_error(cbc_start(self.idx, iv, key, len(key), 0, <symmetric_cbc*>&self.state))
			
		elif self.mode_i == 2:
			check_for_error(ctr_start(self.idx, iv, key, len(key), 0, CTR_COUNTER_BIG_ENDIAN, <symmetric_ctr*>&self.state))
			
		elif self.mode_i == 3:
			check_for_error(cfb_start(self.idx, iv, key, len(key), 0, <symmetric_cfb*>&self.state))
			
		elif self.mode_i == 4:
			check_for_error(ofb_start(self.idx, iv, key, len(key), 0, <symmetric_ofb*>&self.state))
			
		elif self.mode_i == 5:
			tweak = kwargs.get('tweak')
			if not isinstance(tweak, basestring) or len(tweak) != 16:
				raise Error('tweak must be 16 byte string')
			check_for_error(lrw_start(self.idx, iv, key, len(key), tweak, 0, <symmetric_lrw*>&self.state))
			
		elif self.mode_i == 6:
			salt_key = kwargs.get('salt_key')
			if not isinstance(salt_key, basestring):
				raise Error('salt_key must be a string')
			check_for_error(f8_start(self.idx, iv, key, len(key), salt_key, len(salt_key), 0, <symmetric_f8*>&self.state))
			
	cpdef get_iv(self):
		if all_getiv[self.mode_i] == NULL:
			raise Error('%r mode does not use an IV' % self.mode)
		cdef unsigned long length
		length = self.desc.block_size
		iv = PyString_FromStringAndSize(NULL, length)
		check_for_error(all_getiv[self.mode_i](iv, &length, &self.state))
		return iv
	
	cpdef set_iv(self, iv):	
		if all_getiv[self.mode_i] == NULL:
			raise Error('%r mode does not use an IV' % self.mode)
		check_for_error(all_setiv[self.mode_i](iv, len(iv), &self.state))

	cpdef done(self):
		check_for_error(all_done[self.mode_i](&self.state))
	
	cpdef encrypt(self, input):
		"""Encrypt a string."""
		cdef int length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		check_for_error(all_encrypt[self.mode_i](input, output, length, &self.state))
		return output
	
	cpdef decrypt(self, input):
		"""Decrypt a string."""
		cdef int length
		length = len(input)
		# We need to make sure we have a brand new string as it is going to be
		# modified. The input will not be, so we can use the python one.
		output = PyString_FromStringAndSize(NULL, length)
		check_for_error(all_decrypt[self.mode_i](input, output, length, &self.state))
		return output
	

# This is just so that the API is pretty much the same for all the modules
# and to hashlib and hmac in the stdlib.
new = Cipher

# Make some descriptors and informational stuff for convenience
modes = ('ecb', 'cbc', 'ctr', 'cfb', 'ofb', 'lrw', 'f8')
simple_modes = set(['ofb', 'cbc', 'cfb'])
no_iv_modes = set(['ecb'])
iv_modes = set(['ofb', 'cbc', 'lrw', 'ctr', 'f8', 'cfb'])





cipher_descs = {}
try:
	cipher_descs['aes'] = CipherDescriptor('aes')
except ValueError:
	pass
try:
	cipher_descs['blowfish'] = CipherDescriptor('blowfish')
except ValueError:
	pass
try:
	cipher_descs['des'] = CipherDescriptor('des')
except ValueError:
	pass

cipher_modes = {}
def ecb(key, *args, **kwargs):
	"""Cipher constructor for ECB mode."""
	return Cipher(key, *args, mode='ecb', **kwargs)
cipher_modes['ecb'] = ecb
def cbc(key, *args, **kwargs):
	"""Cipher constructor for CBC mode."""
	return Cipher(key, *args, mode='cbc', **kwargs)
cipher_modes['cbc'] = cbc
def ctr(key, *args, **kwargs):
	"""Cipher constructor for CTR mode."""
	return Cipher(key, *args, mode='ctr', **kwargs)
cipher_modes['ctr'] = ctr
def cfb(key, *args, **kwargs):
	"""Cipher constructor for CFB mode."""
	return Cipher(key, *args, mode='cfb', **kwargs)
cipher_modes['cfb'] = cfb
def ofb(key, *args, **kwargs):
	"""Cipher constructor for OFB mode."""
	return Cipher(key, *args, mode='ofb', **kwargs)
cipher_modes['ofb'] = ofb
def lrw(key, *args, **kwargs):
	"""Cipher constructor for LRW mode."""
	return Cipher(key, *args, mode='lrw', **kwargs)
cipher_modes['lrw'] = lrw
def f8(key, *args, **kwargs):
	"""Cipher constructor for F8 mode."""
	return Cipher(key, *args, mode='f8', **kwargs)
cipher_modes['f8'] = f8












def test_hash():
	"""Run the internal tests."""
	register_all_hashes()
	check_for_error(md2_desc.test())
	check_for_error(md4_desc.test())
	check_for_error(md5_desc.test())
	check_for_error(rmd128_desc.test())
	check_for_error(rmd160_desc.test())
	check_for_error(rmd256_desc.test())
	check_for_error(rmd320_desc.test())
	check_for_error(sha1_desc.test())
	check_for_error(sha224_desc.test())
	check_for_error(sha256_desc.test())
	check_for_error(sha384_desc.test())
	check_for_error(sha512_desc.test())
	check_for_error(tiger_desc.test())
	check_for_error(whirlpool_desc.test())


cdef int max_hash_idx = -1
cpdef int get_hash_idx(object input):
	global max_hash_idx
	idx = -1
	if isinstance(input, int):
		idx = input
	elif isinstance(input, basestring):
		idx = find_hash(input)
		if idx == -1:
			if input == 'md2':
				idx = register_hash(&md2_desc)
			elif input == 'md4':
				idx = register_hash(&md4_desc)
			elif input == 'md5':
				idx = register_hash(&md5_desc)
			elif input == 'rmd128':
				idx = register_hash(&rmd128_desc)
			elif input == 'rmd160':
				idx = register_hash(&rmd160_desc)
			elif input == 'rmd256':
				idx = register_hash(&rmd256_desc)
			elif input == 'rmd320':
				idx = register_hash(&rmd320_desc)
			elif input == 'sha1':
				idx = register_hash(&sha1_desc)
			elif input == 'sha224':
				idx = register_hash(&sha224_desc)
			elif input == 'sha256':
				idx = register_hash(&sha256_desc)
			elif input == 'sha384':
				idx = register_hash(&sha384_desc)
			elif input == 'sha512':
				idx = register_hash(&sha512_desc)
			elif input == 'tiger':
				idx = register_hash(&tiger_desc)
			elif input == 'whirlpool':
				idx = register_hash(&whirlpool_desc)
			max_hash_idx = max(idx, max_hash_idx)
	elif isinstance(input, HashDescriptor):
		idx = input.idx
	if idx < 0 or idx > max_hash_idx:
		raise ValueError('could not find hash %r' % input)
	return idx
	
	
cpdef register_all_hashes():
	global max_hash_idx
	max_hash_idx = max(max_hash_idx, register_hash(&md2_desc))
	max_hash_idx = max(max_hash_idx, register_hash(&md4_desc))
	max_hash_idx = max(max_hash_idx, register_hash(&md5_desc))
	max_hash_idx = max(max_hash_idx, register_hash(&rmd128_desc))
	max_hash_idx = max(max_hash_idx, register_hash(&rmd160_desc))
	max_hash_idx = max(max_hash_idx, register_hash(&rmd256_desc))
	max_hash_idx = max(max_hash_idx, register_hash(&rmd320_desc))
	max_hash_idx = max(max_hash_idx, register_hash(&sha1_desc))
	max_hash_idx = max(max_hash_idx, register_hash(&sha224_desc))
	max_hash_idx = max(max_hash_idx, register_hash(&sha256_desc))
	max_hash_idx = max(max_hash_idx, register_hash(&sha384_desc))
	max_hash_idx = max(max_hash_idx, register_hash(&sha512_desc))
	max_hash_idx = max(max_hash_idx, register_hash(&tiger_desc))
	max_hash_idx = max(max_hash_idx, register_hash(&whirlpool_desc))


cdef class HashDescriptor(object):
	
	cdef int idx
	cdef hash_desc desc
	
	def __init__(self, hash):
		self.idx = get_hash_idx(hash)
		self.desc = hash_descriptors[self.idx]

	@property
	def name(self):
		return self.desc.name

	@property
	def digest_size(self):
		return self.desc.digest_size

	@property
	def block_size(self):
		return self.desc.block_size

	def __repr__(self):
		return '<%s.%s of %s>' % (
			self.__class__.__module__, self.__class__.__name__, self.desc.name)
	
	def __call__(self, *args):
		return Hash(self.desc.name, *args)

			
cdef class Hash(HashDescriptor):
	
	cdef hash_state state
	
	def __init__(self, hash, *args):
		HashDescriptor.__init__(self, hash)
		self.init()
		for arg in args:
			self.update(arg)
	
	def __repr__(self):
		return '<%s.%s of %s at 0x%x>' % (
			self.__class__.__module__, self.__class__.__name__, self.name,
			id(self))
	
	cpdef init(self):
		self.desc.init(&self.state)

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
try:
	hash_descs['md2'] = HashDescriptor('md2')
except ValueError:
	pass
try:
	hash_descs['md4'] = HashDescriptor('md4')
except ValueError:
	pass
try:
	hash_descs['md5'] = HashDescriptor('md5')
except ValueError:
	pass
try:
	hash_descs['rmd128'] = HashDescriptor('rmd128')
except ValueError:
	pass
try:
	hash_descs['rmd160'] = HashDescriptor('rmd160')
except ValueError:
	pass
try:
	hash_descs['rmd256'] = HashDescriptor('rmd256')
except ValueError:
	pass
try:
	hash_descs['rmd320'] = HashDescriptor('rmd320')
except ValueError:
	pass
try:
	hash_descs['sha1'] = HashDescriptor('sha1')
except ValueError:
	pass
try:
	hash_descs['sha224'] = HashDescriptor('sha224')
except ValueError:
	pass
try:
	hash_descs['sha256'] = HashDescriptor('sha256')
except ValueError:
	pass
try:
	hash_descs['sha384'] = HashDescriptor('sha384')
except ValueError:
	pass
try:
	hash_descs['sha512'] = HashDescriptor('sha512')
except ValueError:
	pass
try:
	hash_descs['tiger'] = HashDescriptor('tiger')
except ValueError:
	pass
try:
	hash_descs['whirlpool'] = HashDescriptor('whirlpool')
except ValueError:
	pass










def test_mac():
	register_all_hashes()
	check_for_error(hmac_test());

			
cdef class hmac(HashDescriptor):
	
	cdef hmac_state state
	
	def __init__(self, hash, key, *args):
		HashDescriptor.__init__(self, hash)
		self.init(key)
		for arg in args:
			self.update(arg)
	
	def __repr__(self):
		return '<%s.%s of %s at 0x%x>' % (
			self.__class__.__module__, self.__class__.__name__, self.name,
			id(self))
	
	cpdef init(self, key):
		hmac_init(&self.state, self.idx, key, len(key))
	
	cpdef update(self, input):
		check_for_error(hmac_process(&self.state, input, len(input)))
	
	
	cpdef digest(self, length=None):
		if length is None:
			length = self.desc.digest_size
		cdef unsigned long c_len = length
		cdef hmac_state state
		memcpy(&state, &self.state, sizeof(hash_state))
		out = PyString_FromStringAndSize(NULL, self.desc.digest_size)
		check_for_error(hmac_done(&state, out, &c_len))
		return out[:c_len]
	
	def hexdigest(self, *args):
		return self.digest(*args).encode('hex')
	
	cpdef copy(self):
		cdef hmac copy = self.__class__(self.desc.name)
		memcpy(&copy.state, &self.state, sizeof(hmac_state))
		return copy






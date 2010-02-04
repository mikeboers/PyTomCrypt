

cpdef str pkcs5_alg1(str password, str salt, int iteration_count, hash):
	if len(salt) != 8:
		raise Error('salt must be length 8')
	cdef HashDescriptor desc = HashDescriptor(hash)
	cdef unsigned long outlen = desc.digest_size
	out = PyString_FromStringAndSize(NULL, outlen)
	c_pkcs5_alg1(password, len(password), salt, iteration_count, desc.idx, out, &outlen)
	return out[:outlen]


cpdef str pkcs5_alg2(str password, str salt, int iteration_count, hash, unsigned long outlen):	
	cdef HashDescriptor desc = HashDescriptor(hash)
	out = PyString_FromStringAndSize(NULL, outlen)
	c_pkcs5_alg2(password, len(password), salt, len(salt), iteration_count, desc.idx, out, &outlen)
	return out[:outlen]


cpdef pkcs5(str password, str salt='', int iteration_count=1000, hash='sha256', unsigned long outlen=256/8):
	return pkcs5_alg2(password, salt, iteration_count, hash, outlen)


__pkcs5_all__ = ('pkcs5_alg1', 'pkcs5_alg2', 'pkcs5')
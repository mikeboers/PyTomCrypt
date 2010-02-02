
ltc_mp = tfm_desc

def make_rsa_key(PRNG prng, int size=1024/8, long e=65537):
	cdef rsa_key key
	rsa_make_key(&prng.state, prng.idx, size, e, &key)
	print key.type
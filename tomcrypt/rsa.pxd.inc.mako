
cdef extern from "tomcrypt.h" nogil:

	cdef int PK_PUBLIC
	cdef int PK_PRIVATE
	
	ctypedef struct rsa_key:
		int type
	
	int rsa_make_key(prng_state *state, int prng_idx, int size, long e, rsa_key *key)
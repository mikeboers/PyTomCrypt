
cdef extern from "tomcrypt.h" nogil:

	cdef int PK_PUBLIC
	cdef int PK_PRIVATE
	
	ctypedef struct rsa_key:
		int type
	
	ctypedef struct math_desc "ltc_math_descriptor":
		pass
	
	cdef extern math_desc ltc_mp
	# cdef extern math_desc ltm_desc
	cdef extern math_desc tfm_desc
	# math_desc tfm_desc
	# math_desc gmp_desc
	
	int rsa_make_key(prng_state *state, int prng_idx, int size, long e, rsa_key *key)
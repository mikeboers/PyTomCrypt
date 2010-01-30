cdef extern from "stdlib.h" nogil:

	void * malloc(int size)
	void free(void * ptr)
	void * memcpy(void *dest, void *src, size_t num)


from python cimport PyString_FromStringAndSize


cdef extern from "pyerrors.h":
	ctypedef class __builtin__.Exception [object PyBaseExceptionObject]:
		pass


cdef extern from "tomcrypt.h" nogil:

	int CRYPT_OK
	int MAXBLOCKSIZE
	char * error_to_string(int err)
	
	ctypedef struct math_desc "ltc_math_descriptor":
		pass
	
	math_desc ltm_desc
	math_desc tfm_desc
	math_desc gmp_desc
	
	math_desc ltc_mp
	
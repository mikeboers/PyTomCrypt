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
	char * error_to_string(int err)

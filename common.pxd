cdef extern from "stdlib.h":

	void * malloc(int size)
	void free(void * ptr)


cdef extern from "Python.h":

	object PyString_FromStringAndSize(char *s, Py_ssize_t len)
	

cdef extern from "tomcrypt.h":

	int CRYPT_OK
	char * error_to_string(int err)
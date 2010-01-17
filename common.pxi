
cdef extern from "stdlib.h":

	void * malloc(int size)
	void free(void * ptr)
	void * memcpy(void *dest, void *src, size_t num)


cdef extern from "Python.h":

	object PyString_FromStringAndSize(char *s, Py_ssize_t len)


cdef extern from "tomcrypt.h":

	int CRYPT_OK
	char * error_to_string(int err)


# Wrap EVERY call to tomcryptlib in this function!
cdef check_for_error(int res):
	if res != CRYPT_OK:
		raise Error(res)

class Error(Exception):
	def __init__(self, err):
		if isinstance(err, int):
			Exception.__init__(self, error_to_string(err))
		else:
			Exception.__init__(self, err)
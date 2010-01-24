

class Error(Exception):
	def __init__(self, err):
		if isinstance(err, int):
			Exception.__init__(self, error_to_string(err))
		else:
			Exception.__init__(self, err)


cdef inline check_for_error(int res):
	if res != CRYPT_OK:
		raise Error(res)

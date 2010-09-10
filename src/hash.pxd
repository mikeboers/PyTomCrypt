
from tomcrypt._core cimport *

cdef class HashDescriptor(object):
	
	cdef readonly int idx
	cdef hash_desc desc


cpdef register_all_hashes()
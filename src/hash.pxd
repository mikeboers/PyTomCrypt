
from tomcrypt._core cimport *

cdef class Descriptor(object):
	
	cdef readonly int idx
	cdef hash_desc desc
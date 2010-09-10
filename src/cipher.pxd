
from tomcrypt._core cimport cipher_desc

cdef class Descriptor(object):
	
	cdef int idx
	cdef cipher_desc desc
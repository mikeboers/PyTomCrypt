
from tomcrypt._core cimport cipher_desc

cdef class CipherDescriptor(object):
	
	cdef readonly int idx
	cdef cipher_desc desc
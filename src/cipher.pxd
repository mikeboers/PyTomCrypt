from tomcrypt._core cimport cipher_desc

cdef class Descriptor(object):
    
    cdef readonly int idx
    cdef cipher_desc *desc

cdef int get_cipher_idx(object input)

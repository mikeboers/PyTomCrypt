from tomcrypt._core cimport *

cdef class Descriptor(object):
    
    cdef readonly int idx
    cdef hash_desc *desc

cdef get_hash_idx(input)

cdef Descriptor conform_hash(x)


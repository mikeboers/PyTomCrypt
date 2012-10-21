from tomcrypt._core cimport *

# cdef class Descriptor(object):
#     
#     cdef readonly int idx
#     cdef prng_desc *desc

cdef class PRNG(object):
    
    cdef prng_desc *desc
    cdef readonly int idx
    cdef readonly bint ready
    cdef prng_state state

    cdef _autoready(self)
    
cdef get_prng_idx(input)

cdef PRNG conform_prng(prng)



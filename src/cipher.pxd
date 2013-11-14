from tomcrypt._core cimport *

cdef class Descriptor(object):
    
    cdef readonly int idx
    cdef cipher_desc *desc


# Define a type to masquarade as ANY of the mode states.
cdef union symmetric_all:
    % for mode in cipher_no_auth_modes:
    symmetric_${mode} ${mode}
    % endfor
    % for mode in cipher_auth_modes:
    ${mode}_state ${mode}
    % endfor


cdef class Cipher(Descriptor):

    cdef symmetric_all state

    cdef int mode_i
    cdef readonly object mode

    cdef readonly bint missing_iv

    cpdef add_header(self, bytes input_)
    cpdef get_iv(self)
    cpdef set_iv(self, input_)
    cpdef encrypt(self, bytes input_)
    cpdef decrypt(self, bytes input_)
    cpdef done(self)


cdef int get_cipher_idx(object input)

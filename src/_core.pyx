


# Setup TomsFastMath for use.
mp = ltm_desc


cpdef error_to_string(int err):
    # We need to deal with libtomcrypt not defining this error message.
    if err == CRYPT_PK_INVALID_PADDING:
        return "Invalid padding mode."
    # Extra str is for Python 2 to get a native string.
    return str(raw_error_to_string(err).decode())


from tomcrypt import Error, LibError


cdef void check_for_error(int res) except *:
    if res != CRYPT_OK:
        raise LibError(error_to_string(res), code=res)


cdef unsigned char* get_readonly_buffer(object input_, size_t *length) except? NULL:
    
    # Accept something that can be coerced into a writable buffer, or
    # directly into a pointer.
    cdef unsigned char[::1] view
    try:
        view = input_
        length[0] = view.shape[0] * view.itemsize
        return &view[0]
    except BufferError:
        length[0] = len(input_)
        return <unsigned char*>input_





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

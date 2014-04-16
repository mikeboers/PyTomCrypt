

version = str(PTC_VERSION.decode())


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


cdef class ByteSource(object):

    def __cinit__(self, owner):
        self.owner = owner

        try:
            self.ptr = owner
        except TypeError:
            pass
        else:
            self.length = len(owner)
            return

        if PyObject_CheckBuffer(owner):
            res = PyObject_GetBuffer(owner, &self.view, PyBUF_SIMPLE)
            if not res:
                self.has_view = True
                self.ptr = <unsigned char *>self.view.buf
                self.length = self.view.len
                return
        
        raise TypeError('expected bytes, bytearray or memoryview')

    def __dealloc__(self):
        if self.has_view:
            PyBuffer_Release(&self.view)


cdef ByteSource bytesource(obj, bint allow_none=False):
    if allow_none and obj is None:
        return
    elif isinstance(obj, ByteSource):
        return obj
    else:
        return ByteSource(obj)


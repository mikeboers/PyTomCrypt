from tomcrypt._core cimport *
from tomcrypt.hash cimport Descriptor as HashDescriptor, conform_hash
from tomcrypt import Error


cpdef bytes pkcs5_alg1(password, salt, int iteration_count, hash):
    cdef ByteSource c_pass = bytesource(password)
    cdef ByteSource c_salt = bytesource(salt)
    if c_salt.length != 8:
        raise Error('salt must be length 8')
    cdef HashDescriptor desc = conform_hash(hash)
    cdef unsigned long outlen = desc.digest_size
    out = PyBytes_FromStringAndSize(NULL, outlen)
    c_pkcs5_alg1(c_pass.ptr, c_pass.length, c_salt.ptr, iteration_count, desc.idx, out, &outlen)
    return out[:outlen]


cpdef bytes pkcs5_alg2(password, salt, int iteration_count, hash):
    r"""pkcs5(password, salt, iteration_count, hash)

    Calculates PKCS #5 Password-based Encryption Standard (version 2) of a
    given string with a given salt.

    :param bytes password: The password to hash.
    :param bytes salt: The salt to use.
    :param int iteration_count: The number of times to hash.
    :param hash: The algorithm to use: a ``str`` or :class:`hash.Descriptor <tomcrypt.hash.Descriptor>`.

    ::

        >>> pkcs5(b'password', salt='salt', iteration_count=1024, hash='sha256')
        b'#\x1a\xfb}\xcd.\x86\x0c\xfdX\xab\x137+\xd1,\x920v\xc3Y\x8a\x12\x19`2\x0fo\xec\x8aV\x98'

    """

    cdef ByteSource c_pass = bytesource(password)
    cdef ByteSource c_salt = bytesource(salt)
    cdef HashDescriptor desc = conform_hash(hash)
    cdef unsigned long outlen = desc.digest_size
    out = PyBytes_FromStringAndSize(NULL, outlen)
    c_pkcs5_alg2(c_pass.ptr, c_pass.length, c_salt.ptr, c_salt.length, iteration_count, desc.idx, out, &outlen)
    return out[:outlen]


pkcs5 = pkcs5_alg2





cdef extern from "pytomcrypt.h" nogil:
    pass

cdef extern from "stdlib.h" nogil:

    void * malloc(int size)
    void free(void * ptr)
    void * memcpy(void *dest, void *src, size_t num)


from cpython.version cimport PY_MAJOR_VERSION
from cpython cimport PyBytes_FromStringAndSize


cdef extern from "pyerrors.h":
    ctypedef class __builtin__.Exception [object PyBaseExceptionObject]:
        pass


cdef extern from "tomcrypt.h" nogil:

    int CRYPT_OK
    int CRYPT_INVALID_PACKET
    int CRYPT_PK_INVALID_PADDING
    
    int MAXBLOCKSIZE
    
    char * raw_error_to_string "error_to_string"(int err)
    
    ctypedef struct math_desc "ltc_math_descriptor":
        char * name
        
        # Initialise a bignum.
        int init(void **a)
        
        # Copy-init a bignum.
        int init_copy(void **dst, void *src)
        
        # Deinit.
        int deinit(void *a)
        
        int copy(void *src, void *dst)
        int set_int(void *a, unsigned long n)
        unsigned long get_int(void *a)
        
        unsigned long get_digit(void *a, int n)
        int get_digit_count(void *a)
        
        int count_bits(void *a)
        int count_lsb_bits(void *a)
        
        # Read/write in a specific radix (base)
        int read_radix(void *a, char *str, int radix)
        int write_radix(void *a, char *str, int radix)
        
        # Read/write full binary.
        unsigned long unsigned_size(void *a)
        int unsigned_write(void *a, unsigned char *b)
        int unsigned_read(void *a, unsigned char *b, unsigned long len)
        
    
    # math_desc ltm_desc
    cdef extern math_desc ltm_desc
    # math_desc gmp_desc
    
    cdef extern math_desc mp "ltc_mp"



# Prototypes
cdef void check_for_error(int res) except *


include "tomcrypt.cipher-core.pxd"
include "tomcrypt.hash-core.pxd"
include "tomcrypt.mac-core.pxd"
include "tomcrypt.prng-core.pxd"
include "tomcrypt.rsa-core.pxd"
include "tomcrypt.pkcs1-core.pxd"
include "tomcrypt.pkcs5-core.pxd"
include "tomcrypt.ecc-core.pxd"


cdef extern from "stdlib.h" nogil:

	void * malloc(int size)
	void free(void * ptr)
	void * memcpy(void *dest, void *src, size_t num)


from python cimport PyString_FromStringAndSize


cdef extern from "pyerrors.h":
	ctypedef class __builtin__.Exception [object PyBaseExceptionObject]:
		pass


cdef extern from "tomcrypt.h" nogil:

	int CRYPT_OK
	int MAXBLOCKSIZE
	
	char * error_to_string(int err)
	
	ctypedef struct math_desc "ltc_math_descriptor":
		char * name
		
		# Initialise a bignum.
		int init(void **a)
		
		# Copy-init a bignum.
		int init_copy(void **dst, void**src)
		
		# Deinit.
		int deinit(void *a)
		
		int copy(void *src, void *dst)
		int set_int(void *a, unsigned long n)
		unsigned long get_int(void *a)
		
		unsigned long get_digit(void *a, int n)
		int get_digit_count(void *a)
		
		int count_bits(void *a)
		int count_lsb_bits(void *a)
		
		int read_radix(void *a, char *str, int radix)
		int write_radix(void *a, char *str, int radix)
	
	# math_desc ltm_desc
	cdef extern math_desc tfm_desc
	# math_desc gmp_desc
	
	cdef extern math_desc mp "ltc_mp"
	
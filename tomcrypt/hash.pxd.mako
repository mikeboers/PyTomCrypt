<%

DO_HASH = hash_do_hash = ext_name == 'hash'
DO_MAC  = hash_do_hmac = not DO_HASH

hash_class_name = 'Hash' if hash_do_hash else 'HMAC'
hash_type = hash_class_name.lower()

%>


cdef extern from "tomcrypt.h":
	
	cdef union hash_state "Hash_state":
		pass
	
	cdef struct hmac_state "Hmac_state":
		pass
	
	# Hash descriptor.
	cdef struct hash_desc "ltc_hash_descriptor":
		char * name
		unsigned long digest_size "hashsize"
		unsigned long block_size "blocksize"
		void init(hash_state *md)
		int process(hash_state *md, unsigned char *input, unsigned long inputlen)
		int done(hash_state *md, unsigned char *out)
		int test()
	
	# The array which contains the descriptors once setup.
	hash_desc hash_descriptors "hash_descriptor" []
	
	# The descriptors themselves.
	% for name in hash_names:
	hash_desc ${name}_desc
	% endfor
		
	# Functions for registering and finding the registered hashs.
	int register_hash(hash_desc *hash)
	int find_hash(char * name)
	
	# HMAC
	int hmac_test()
	int hmac_init(hmac_state *, int, unsigned char *, unsigned long)
	int hmac_process(hmac_state *, unsigned char *, unsigned long)
	int hmac_done(hmac_state *, unsigned char *, unsigned long *)


% if DO_HASH:
cpdef int get_hash_idx(object input)

cdef class Descriptor(object):
	cdef readonly int idx
	cdef hash_desc desc


% endif
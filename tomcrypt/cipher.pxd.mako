
cdef extern from "tomcrypt.h":

	int CTR_COUNTER_BIG_ENDIAN
	
	# Symmetric state for all the modes.
	% for name in modes:
	ctypedef struct symmetric_${name} "symmetric_${name.upper()}":
		pass
	% endfor
	
	# Pull in all the cipher functions for all the modes.
	int ecb_start(int cipher, unsigned char *key, int keylen, int num_rounds, symmetric_ecb *ecb)
	int ctr_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, int ctr_mode, symmetric_ctr *ctr)
	% for name in simple_modes:
	int ${name}_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, symmetric_${name} *${name})
	% endfor
	int lrw_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, unsigned char *tweak, int num_rounds, symmetric_lrw *lrw)
	int f8_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, unsigned char *salt_key, int skeylen, int num_rounds, symmetric_f8 *f8)
	% for name in modes:
	int ${name}_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_${name} *${name})
	int ${name}_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_${name} *${name})
	int ${name}_done(void *${name})
	% endfor
	% for name in iv_modes:
	int ${name}_getiv(unsigned char *iv, unsigned long *len, symmetric_${name} *${name})
	int ${name}_setiv(unsigned char *iv, unsigned long len, symmetric_${name} *${name})
	% endfor
	
	# Cipher descriptor.
	cdef struct cipher_desc "ltc_cipher_descriptor":
		char * name
		int min_key_size "min_key_length"
		int max_key_size "max_key_length"
		int block_size "block_length"
		int default_rounds
		int key_size "keysize" (int *key_size)
		# int setup(char *key, int keylen, int rounds, symmetric_key *skey)
	
	# The array which contains the descriptors once setup.
	cipher_desc cipher_descriptors "cipher_descriptor" []
	
	# The descriptors themselves.
	% for name in ciphers:
	cipher_desc ${name}_desc
	int ${name}_test()
	% endfor
		
	# Functions for registering and finding the registered ciphers.
	int register_cipher(cipher_desc *cipher)
	int find_cipher(char * name)
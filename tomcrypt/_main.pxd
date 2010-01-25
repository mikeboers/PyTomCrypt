

cdef extern from "tomcrypt.h":

	int CTR_COUNTER_BIG_ENDIAN
	
	# Symmetric state for all the cipher modes.
	ctypedef struct symmetric_ofb "symmetric_OFB":
		pass
	ctypedef struct symmetric_cbc "symmetric_CBC":
		pass
	ctypedef struct symmetric_ecb "symmetric_ECB":
		pass
	ctypedef struct symmetric_ctr "symmetric_CTR":
		pass
	ctypedef struct symmetric_f8 "symmetric_F8":
		pass
	ctypedef struct symmetric_cfb "symmetric_CFB":
		pass
	ctypedef struct symmetric_lrw "symmetric_LRW":
		pass
	
	# Pull in all the cipher functions for all the modes.
	int ecb_start(int cipher, unsigned char *key, int keylen, int num_rounds, symmetric_ecb *ecb)
	int ctr_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, int ctr_mode, symmetric_ctr *ctr)
	int ofb_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, symmetric_ofb *ofb)
	int cbc_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, symmetric_cbc *cbc)
	int cfb_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, int num_rounds, symmetric_cfb *cfb)
	int lrw_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, unsigned char *tweak, int num_rounds, symmetric_lrw *lrw)
	int f8_start(int cipher, unsigned char *iv, unsigned char *key, int keylen, unsigned char *salt_key, int skeylen, int num_rounds, symmetric_f8 *f8)
	int ofb_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_ofb *ofb)
	int ofb_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_ofb *ofb)
	int ofb_done(void *ofb)
	int cbc_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_cbc *cbc)
	int cbc_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_cbc *cbc)
	int cbc_done(void *cbc)
	int ecb_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_ecb *ecb)
	int ecb_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_ecb *ecb)
	int ecb_done(void *ecb)
	int ctr_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_ctr *ctr)
	int ctr_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_ctr *ctr)
	int ctr_done(void *ctr)
	int f8_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_f8 *f8)
	int f8_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_f8 *f8)
	int f8_done(void *f8)
	int cfb_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_cfb *cfb)
	int cfb_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_cfb *cfb)
	int cfb_done(void *cfb)
	int lrw_encrypt(unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_lrw *lrw)
	int lrw_decrypt(unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_lrw *lrw)
	int lrw_done(void *lrw)
	int ofb_getiv(unsigned char *iv, unsigned long *len, symmetric_ofb *ofb)
	int ofb_setiv(unsigned char *iv, unsigned long len, symmetric_ofb *ofb)
	int cbc_getiv(unsigned char *iv, unsigned long *len, symmetric_cbc *cbc)
	int cbc_setiv(unsigned char *iv, unsigned long len, symmetric_cbc *cbc)
	int ctr_getiv(unsigned char *iv, unsigned long *len, symmetric_ctr *ctr)
	int ctr_setiv(unsigned char *iv, unsigned long len, symmetric_ctr *ctr)
	int f8_getiv(unsigned char *iv, unsigned long *len, symmetric_f8 *f8)
	int f8_setiv(unsigned char *iv, unsigned long len, symmetric_f8 *f8)
	int cfb_getiv(unsigned char *iv, unsigned long *len, symmetric_cfb *cfb)
	int cfb_setiv(unsigned char *iv, unsigned long len, symmetric_cfb *cfb)
	int lrw_getiv(unsigned char *iv, unsigned long *len, symmetric_lrw *lrw)
	int lrw_setiv(unsigned char *iv, unsigned long len, symmetric_lrw *lrw)
	
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
	cipher_desc aes_desc
	int aes_test()
	cipher_desc blowfish_desc
	int blowfish_test()
	cipher_desc des_desc
	int des_test()
		
	# Functions for registering and finding the registered ciphers.
	int register_cipher(cipher_desc *cipher)
	int find_cipher(char * name)

cpdef int get_cipher_idx(object input)
cpdef register_all_ciphers()










cdef extern from "tomcrypt.h":
	
	cdef union hash_state "Hash_state":
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
	hash_desc md2_desc
	hash_desc md4_desc
	hash_desc md5_desc
	hash_desc rmd128_desc
	hash_desc rmd160_desc
	hash_desc rmd256_desc
	hash_desc rmd320_desc
	hash_desc sha1_desc
	hash_desc sha224_desc
	hash_desc sha256_desc
	hash_desc sha384_desc
	hash_desc sha512_desc
	hash_desc tiger_desc
	hash_desc whirlpool_desc
		
	# Functions for registering and finding the registered hashs.
	int register_hash(hash_desc *hash)
	int find_hash(char * name)


cpdef int get_hash_idx(object input)
cpdef register_all_hashes()






cdef extern from "tomcrypt.h":
	
	cdef struct hmac_state "Hmac_state":
		pass
	
	int hmac_test()
	int hmac_init(hmac_state *, int, unsigned char *, unsigned long)
	int hmac_process(hmac_state *, unsigned char *, unsigned long)
	int hmac_done(hmac_state *, unsigned char *, unsigned long *)










cdef extern from "tomcrypt.h":
	
	cdef struct hmac_state "Hmac_state":
		pass
	
	int hmac_test()
	int hmac_init(hmac_state *, int, unsigned char *, unsigned long)
	int hmac_process(hmac_state *, unsigned char *, unsigned long)
	int hmac_done(hmac_state *, unsigned char *, unsigned long *)


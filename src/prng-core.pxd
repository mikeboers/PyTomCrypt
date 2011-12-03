cdef extern from "tomcrypt.h" nogil:

    ctypedef struct prng_state:
        pass
    
    
    # Cipher descriptor.
    cdef struct prng_desc "ltc_prng_descriptor":
        char * name
        int export_size
        int start(prng_state *)
        int add_entropy(unsigned char *, unsigned long, prng_state *)
        int ready(prng_state *)
        unsigned long read(unsigned char *, unsigned long, prng_state *)
        void done(prng_state *)
        int get_state "pexport" (unsigned char *, unsigned long *, prng_state *)
        int set_state "pimport" (unsigned char *, unsigned long  , prng_state *)
        int test()
    
    # The array which contains the descriptors once setup.
    prng_desc prng_descriptors "prng_descriptor" []
    
    # The descriptors themselves.
    % for name in prng_names:
    prng_desc ${name}_desc
    % endfor
        
    # Functions for registering and finding the registered prngs.
    int register_prng(prng_desc *prng)
    int find_prng(char * name)
    
    unsigned long rng_get_bytes(unsigned char *buf, unsigned long len, void (*callback)())
    int rng_make_prng(int bits, int wprng, prng_state *prng, void (*callback)())



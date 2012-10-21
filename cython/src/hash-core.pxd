cdef extern from "tomcrypt.h" nogil:

    ctypedef union hash_state:
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
    
    int chc_register(int)



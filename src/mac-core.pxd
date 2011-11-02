cdef extern from "tomcrypt.h" nogil:

    ctypedef struct hmac_state:
        hash_state     md
        int            hash
        hash_state     hashstate
        unsigned char *key
    
    % for mode in 'omac', 'pmac', 'xcbc':
    ctypedef struct ${mode}_state:
        pass
    
    % endfor
    % for mac in mac_names:
    int ${mac}_test()
    int ${mac}_init(${mac}_state *, int, unsigned char *, unsigned long)
    int ${mac}_process(${mac}_state *, unsigned char *, unsigned long)
    int ${mac}_done(${mac}_state *, unsigned char *, unsigned long *)
    
    % endfor

Completeness
============

PyTomCrypt does not yet wrap the entirety of LibTomCrypt; this is planned in the future. Currently, this package provides:

- symmetric ciphers
    - **no** CTR mode flags (page 38 of ltc PDF)
    - **incomplete** auth modes (EAX, but no OCB, CCM, GCM, etc.)
- hashes
- MACs
- pseudo random number generators
- pkcs5
- RSA private/public keys
    - **no** separate padding functions
- **incomplete** ECC
- **no** DSA

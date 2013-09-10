0.8.0
-----
- Fixed RC4 and Sober128 PRNG output. These were dependent upon calling
  conditions and have been made to pass known test vectors.
- ECB cipher mode only accepts `None` as an IV.
- Non-ECB cipher modes no longer accept `None` as an IV.

0.7.0
-----
- Sphinx-based API documentation.
- Dropped "kseed" cipher due to compiling issues on OS X.

0.6.1
-----
- Doctests on nearly everything.
- Fixed CHC bug; it was completely broken.

0.6.0
-----
- Python 3 compatibility.
- Cipher EAX mode.
- ECC implemented.
- Substantially cleaner build process.
- Removed redundant RSA functions `generate_key` and `key_from_string`.

0.5.7
-----
- Fixed `rsa.Key.as_string()` bug (private keys were marked as public).
- Added explicit `rsa.Key.auto_seed(length)`

0.5.6
-----
- Removed `-rdynamic` compilation flag as it is now unnesesary.

0.5.5
-----
- Added some dylib magic for Linux.
- PRNGs auto start.

0.5.4
-----
- Compilation fix.

0.5.3
-----
- Manifest fix.
- BROKEN; DO NOT USE!

0.5.2
-----
- Start of versioned history.
- BROKEN; DO NOT USE!

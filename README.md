
PyTomCrypt
==========

This package is a Python 2/3 wrapper around LibTomCrypt. The API is designed to be conceptually similar to LibTomCrypt, but to be as "Pythonic" as possible.

[Read the Docs](http://mikeboers.github.io/PyTomCrypt/), and good luck!


Limitations
-----------

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


Installation
------------

To get the latest stable release (use `easy_install` if you don't have `pip`):

    $ pip install PyTomCrypt

If you already have the PyPi source distribution, you only need run:

    $ python setup.py install

If you have the original source (ie. from GitHub):

    # Install "mako" and "cython"; they are required to generate the C source of the primary module.
    $ pip install mako cython
    
    # Grab libtomcrypt and libtommath.
    $ git submodule init
    $ git submodule update

    # Preprocess the Cython sources.
    $ make sources
    
    # Build the package.
    $ python setup.py build
    
    # Install the module.
    $ python setup.py install



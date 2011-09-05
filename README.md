
PyTomCrypt
==========

This package is a Python wrapper around LibTomCrypt. The API is designed to be conceptually similar to LibTomCrypt, but to be as "Pythonic" as possible. PyTomCrypt does not yet wrap the entirety of LibTomCrypt; this is planned in the future. Currently, this package provides:

- symmetric ciphers
    - **no** CTR mode flags (page 38 of ltc PDF)
    - **no** auth modes (EAX, OCB, CCM, GCM, etc.)
- hashes
- MACs
- pseudo random number generators
    - **no** import/export functions
- RSA private/public keys
    - **no** separate padding functions
- **no** ECC
- **no** DSA



Installation
=============

To get the latest stable release (use `easy_install` if you don't have `pip`):

    $ pip install PyTomCrypt

If you already have the PyPi source distribution, you only need run:

    $ python setup.py install

If you have the original source (ie. from GitHub):

    # Install "mako" and "cython"; they are required to generate the C source of the primary module.
    $ pip install mako cython
 
    # Build the C source.
    $ make src/_main.c
    
    # Build the module.    
    $ python setup.py build
    
    # Install the module.
    $ python setup.py install


Basic Usage
============
    
Symmetric Ciphers
------------------

    >>> from tomcrypt import cipher

This module contains a `Descriptor` class which describes a cipher, and a `Cipher` class for using a cipher (eg. keys, IVs, etc.). As a convenience there is a pre-made `Descriptor` for every cipher provided.

The module also contains a list of the names of all ciphers provided, and the modes that they can operate in:

    >>> sorted(cipher.names)
    ['aes', 'anubis', 'blowfish', 'cast5', 'des', 'des3', 'kasumi', 'khazad', 'kseed', 'noekeon', 'rc2', 'rc5', 'rc6', 'rijndael', 'saferp', 'twofish', 'xtea']
    >>> sorted(cipher.modes)
    ['cbc', 'cfb', 'ctr', 'ecb', 'f8', 'lrw', 'ofb']
    
We can inspect some of the properties of a cipher via attributes on a `Descriptor` or `Cipher`:

    >>> cipher.aes.block_size
    16
    >>> cipher.aes.min_key_size
    16
    >>> cipher.aes.max_key_size
    32

`Descriptor.key_size` returns the size of the largest key than can be constructed from a string of a given size:

    >>> cipher.aes.key_size(18)
    16

We can construct a `Cipher` object directly (and pass a cipher name via the `cipher` kwarg) or, as a shortcut, use an instantiated `Descriptor` as a factory. You can pass a `key`, `iv`, `cipher` (if calling `Cipher`; defaults to "aes"), `mode` (defaults to "ctr"), `tweak` (only for "lrw" mode), and `salt_key` (only for "f8" mode).

    >>> encryptor = cipher.Cipher(key='0123456789abcdef', iv='0123456789abcdef', cipher='aes', mode='ctr')
    >>> # OR
    >>> encryptor = cipher.aes(key='0123456789abcdef', iv='0123456789abcdef', mode='ctr')

    >>> message = encryptor.encrypt('This is a message')
    >>> message
    '&\x1a\x17\xfb>\xb5\x8e!a\x87u\r\nz\xd4\x02\x94'
    
    >>> decryptor = cipher.aes(key='0123456789abcdef', iv='0123456789abcdef', mode='ctr')
    >>> decryptor.decrypt(message)
    'This is a message'

For those modes which support an IV, you can explicitly get and set it via `get_iv` and `set_iv` methods.


Hashes
-------

    >>> from tomcrypt import hash

This module contains a `Descriptor` class which describes a hash, and a `Hash` class for using a hash. As a convenience there is a pre-made `Descriptor` for every hash provided.

    >>> hasher = hash.Hash('sha256')
    >>> # OR:
    >>> hasher = hash.sha256()

The module also contains a list of the names of all hashes provided:

    >>> sorted(hash.names)
    ['chc', 'md2', 'md4', 'md5', 'rmd128', 'rmd160', 'rmd256', 'rmd320', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'tiger', 'whirlpool']

The module has been designed to be a drop-in replacement for `hashlib` (`new` is simply another name for `Hash`).

    >>> hasher = hash.new('sha256')

You can also provide initial content:

    >>> hasher = hash.Hash('sha256', 'intial')
    >>> # OR:
    >>> hasher = hash.new('sha256', 'intial')
    >>> # OR:
    >>> hasher = hash.sha256('intial')

The rest of the API is the same as hashlib as well:

    >>> # Digests!
    >>> hasher = hash.sha256('initial')
    >>> hasher.hexdigest()
    'ac1b5c0961a7269b6a053ee64276ed0e20a7f48aefb9f67519539d23aaf10149'
    
    >>> # Copies!
    >>> copy = hasher.copy()
    >>> hasher.update('something')
    >>> copy.hexdigest()
    'ac1b5c0961a7269b6a053ee64276ed0e20a7f48aefb9f67519539d23aaf10149'
    
    >>> # Binary output!
    >>> hasher.hexdigest()
    '2e917b6429310675c7b8020885cbce99f64482a36dba5ee323e9891b8afe1545'
    >>> hasher.digest()
    '.\x91{d)1\x06u\xc7\xb8\x02\x08\x85\xcb\xce\x99\xf6D\x82\xa3m\xba^\xe3#\xe9\x89\x1b\x8a\xfe\x15E'



Message Authentication Codes (MACs)
-------------------------------------

    >>> from tomcrypt import mac

This module contains a `MAC` class, and a convenience function for every MAC provided.

    >>> mymac = mac.MAC('hmac', 'sha256', 'secret')
    >>> # OR
    >>> mymac = mac.hmac('sha256', 'secret')

The module also contains a list of the names of all MACS provided, and lists of those which use ciphers or hashes:

    >>> sorted(mac.names)
    ['hmac', 'omac', 'pmac', 'xcbc']
    >>> sorted(mac.hash_macs)
    ['hmac']
    >>> sorted(mac.cipher_macs)
    ['omac', 'pmac', 'xcbc']

The `MAC` will accept either a name or a `Descriptor` to specify which hash/cipher algorithm to use.

    >>> mac.hmac('md5', 'secret', 'content').hexdigest()
    '97e5f3684213a40aaaa9ef31f9f4b1a7'
    >>> mac.hmac(hash.md5, 'secret', 'content').hexdigest()
    '97e5f3684213a40aaaa9ef31f9f4b1a7'
    
    >>> mac.pmac('aes', '0123456789abcdef', 'content').hexdigest()
    '530566cd1c33e874f503b3c3272d0fd4'
    >>> mac.pmac(cipher.aes, '0123456789abcdef', 'content').hexdigest()
    '530566cd1c33e874f503b3c3272d0fd4'

The rest of the API is similar to the stdlib `hmac` (or `hashlib` or `tomcrypt.hash`, etc.), offering `update`, `digest`, `hexdigest`, and `copy` methods.


Pseudo Random Number Generators (PRNGs)
----------------------------------------

    >>> from tomcrypt import prng

This module contains a `PRNG` class which contains all state required for a PRNG, and a convenience function for every PRNG provided.

    >>> myrng = prng.PRNG('yarrow')
    >>> # OR
    >>> myrng = prng.yarrow()

The module also contains a list of the names of all PRNGs provided:

    >>> sorted(prng.names)
    ['fortuna', 'rc4', 'sober128', 'sprng', 'yarrow']

You can add entropy via the add_entropy method:

    >>> myrng = prng.yarrow()
    >>> myrng.add_entropy('hello')
    >>> myrng.read(8).encode('hex')
    'f34a113448ead699'

You can use the system `PRNG` (eg. `/dev/urandom`) to auto-seed your `PRNG`, either at construction or any time afterwards:

    >>> # Seed with 1024 bytes from system PRNG.
    >>> myrng = prng.yarrow(1024)
    >>> myrng.read(8).encode('hex')
    <will always be different>
    >>> # Add another 1024 bytes from system PRNG.
    >>> myrng.auto_seed(1024)
    >>> myrng.read(8).encode('hex')
    <will always be different>

The system PRNG is also directly available via the same API as the "sprng" object.


    


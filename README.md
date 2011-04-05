
PyTomCrypt
==========

This project is a Python wrapper around LibTomCrypt.


Installation
=============

If you have the PyPi distribution, you only need run:

    $ python setup.py install

If you have the source:

1. Install "mako" and "cython"; they are required to generate the C
   source of the primary module.

2. Build the C source:
    
        $ make src/_main.c
    
3. Build the module:
    
        $ python setup.py build
    
4. Install the module:
    
        $ python setup.py install


Basic Usage
============

    # Import the basics.
    from tomcrypt import cipher, hash, mac
    
Symmetric Ciphers
------------------

    print cipher.names
    # set(['noekeon', 'aes', 'des', 'rc5', 'anubis', 'saferp', 'blowfish', 'rc2', 'des3', 'twofish', 'kasumi', 'khazad', 'xtea', 'rijndael', 'cast5', 'rc6', 'kseed'])
    
    print cipher.modes
    # set(['ofb', 'cbc', 'ecb', 'ctr', 'f8', 'cfb', 'lrw'])

    # Defaults to CTR mode; override via "mode" kwarg.
    encryptor = cipher.aes('0123456789abcdef')
    message = encryptor.encrypt("This is a message")

    decryptor = cipher.aes('0123456789abcdef')
    plaintext = decryptor.decrypt(message)


Hashes
-------

    print hash.names
    # set(['rmd160', 'chc', 'rmd256', 'sha224', 'md5', 'tiger', 'sha1', 'rmd320', 'rmd128', 'sha384', 'md2', 'sha256', 'sha512', 'md4', 'whirlpool'])
    
    # These have been designed to have exactly the same API as the built in
    # hashlib.
    
    from tomcrypt.hash import Hash
    hasher = hash.sha256()
    hasher.update('something to hash')
    print hasher.hexdigest()


MACs
-----

    print mac.names
    # set(['omac', 'hmac', 'xcbc', 'pmac'])
    
    mymac = mac.hmac('sha256', 'secret key')
    mymac.update('something to mac')
    print mymac.hexdigest()


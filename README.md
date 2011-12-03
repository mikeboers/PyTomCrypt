
PyTomCrypt
==========

This package is a Python 2/3 wrapper around LibTomCrypt. The API is designed to be conceptually similar to LibTomCrypt, but to be as "Pythonic" as possible. PyTomCrypt does not yet wrap the entirety of LibTomCrypt; this is planned in the future. Currently, this package provides:

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
=============

To get the latest stable release (use `easy_install` if you don't have `pip`):

    $ pip install PyTomCrypt

If you already have the PyPi source distribution, you only need run:

    $ python setup.py install

If you have the original source (ie. from GitHub):

    # Install "mako" and "cython"; they are required to generate the C source of the primary module.
    $ pip install mako cython
 
    # Preprocess the Cython sources.
    $ make sources
    
    # Build the package.
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

    >>> encryptor = cipher.Cipher(key=b'0123456789abcdef', iv=b'0123456789abcdef', cipher='aes', mode='ctr')
    >>> # OR
    >>> encryptor = cipher.aes(key=b'0123456789abcdef', iv=b'0123456789abcdef', mode='ctr')

    >>> message = encryptor.encrypt(b'This is a message')
    >>> message
    b'&\x1a\x17\xfb>\xb5\x8e!a\x87u\r\nz\xd4\x02\x94'
    
    >>> decryptor = cipher.aes(key=b'0123456789abcdef', iv=b'0123456789abcdef', mode='ctr')
    >>> decryptor.decrypt(message)
    b'This is a message'

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

    >>> hasher = hash.Hash('sha256', b'intial')
    >>> # OR:
    >>> hasher = hash.new('sha256', b'intial')
    >>> # OR:
    >>> hasher = hash.sha256(b'intial')

The rest of the API is the same as hashlib as well:

    >>> # Digests!
    >>> hasher = hash.sha256(b'initial')
    >>> hasher.hexdigest()
    'ac1b5c0961a7269b6a053ee64276ed0e20a7f48aefb9f67519539d23aaf10149'
    
    >>> # Copies!
    >>> copy = hasher.copy()
    >>> hasher.update(b'something')
    >>> copy.hexdigest()
    'ac1b5c0961a7269b6a053ee64276ed0e20a7f48aefb9f67519539d23aaf10149'
    
    >>> # Binary output!
    >>> hasher.hexdigest()
    '2e917b6429310675c7b8020885cbce99f64482a36dba5ee323e9891b8afe1545'
    >>> hasher.digest()
    b'.\x91{d)1\x06u\xc7\xb8\x02\x08\x85\xcb\xce\x99\xf6D\x82\xa3m\xba^\xe3#\xe9\x89\x1b\x8a\xfe\x15E'



Message Authentication Codes (MACs)
-------------------------------------

    >>> from tomcrypt import mac

This module contains a `MAC` class, and a convenience function for every MAC provided.

    >>> mymac = mac.MAC('hmac', 'sha256', b'secret')
    >>> # OR
    >>> mymac = mac.hmac('sha256', b'secret')

The module also contains a list of the names of all MACS provided, and lists of those which use ciphers or hashes:

    >>> sorted(mac.names)
    ['hmac', 'omac', 'pmac', 'xcbc']
    >>> sorted(mac.hash_macs)
    ['hmac']
    >>> sorted(mac.cipher_macs)
    ['omac', 'pmac', 'xcbc']

The `MAC` will accept either a name or a `Descriptor` to specify which hash/cipher algorithm to use.

    >>> mac.hmac('md5', b'secret', b'content').hexdigest()
    '97e5f3684213a40aaaa9ef31f9f4b1a7'
    >>> mac.hmac(hash.md5, b'secret', b'content').hexdigest()
    '97e5f3684213a40aaaa9ef31f9f4b1a7'
    
    >>> mac.pmac('aes', b'0123456789abcdef', b'content').hexdigest()
    '530566cd1c33e874f503b3c3272d0fd4'
    >>> mac.pmac(cipher.aes, b'0123456789abcdef', b'content').hexdigest()
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
    b'f34a113448ead699'

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


PKCS5
------

    >>> from tomcrypt.pkcs5 import pkcs5
    
This module contains a function which performs the pkcs5 password hashing scheme. Arguments are available to specify the iteration count (defaults to 1024), hash algo (defaults to sha256), and the hash length (defaults to the full hash).

    >>> pkcs5(b'password', salt='salt', iteration_count=1024, hash='sha256')
    b'#\x1a\xfb}\xcd.\x86\x0c\xfdX\xab\x137+\xd1,\x920v\xc3Y\x8a\x12\x19`2\x0fo\xec\x8aV\x98'
    

RSA
====

    >>> from tomcrypt import rsa

This module contains a `Key` class for encrypting, decrypting, signing, and verifying data with a RSA private or public key.

By default the keys will use `"oaep"` and `"pss"` padding, but you can manually specify `"v1.5"` or `"none"` via the `padding` keyword arg on many methods.

By default the keys will use `sha1` for part of the encryption padding, and `sha512` for the signature, but these can be changed via the `hash` keyword arg on many methods.

You can generate new keys:

    >>> key = rsa.Key(1024)

Or you can load an existing key from a string:

    >>> key = rsa.Key('''-----BEGIN RSA PRIVATE KEY-----
    MIICXwIBAAKBgQv9V1DrxfhDt56rC1/i18HJE6x/SLs2xu5IDySxI0xhme8U6T6w
    Ess275MacdQMSZh5MJl+8YRErwx6zOilDz8y2GDqKrsuMgAodkvfKAeQlQZp+IPZ
    dJlRhoE1Lk/aHBOiqRGR75LufiTAbaDMG3NWM1SidE9qVZv3HsWJqQU7ywIDAQAB
    AoGBBbw8ppMCco5CKf58RHQI7cQ4Sw3gRt4fLyD9TXoG/qS5tCp2oOwtMVSoKeA+
    j0cJdYyTePnGopUQf5HGr4s1zew14Ks2/91J70MEiABvrvVv9ZfiLT1e9/U/HdYE
    s9Vv4NOpStZHhTcUrQXtiEBG+8VQhCIeuW1J9XKT8gTa7A+xAkED/rTemeSV9hQa
    r9gJ4IHWVgJSNMm4A3bWsEM2R9Dm0Iwif8R/RHHJrsHgTKukYOOwbW7RFHwh+QVU
    fL4pXjVR9wJBAwBORpdlEgWAD4IQK0CR6w3htz7w3KrS6OuckEPItA+W9Edt1n/a
    v8Q7FiIdoHWPI4qaCI1g1GlOCUyXtaJb780CQQDKdafzs0r0sjouQYiDB3EVCdSY
    Wq6xEN+jeUrPoM1wz60suguv0w7oJ71tsDUUcT7GC0Ac3A4lrCZzo3mxCsE1AkEA
    419G7tj/a1dJv6EPW82TNYl+FIdtlrRSMCAmZZkJCLAQ3O65kx7mr6kY1MHV0dSp
    nQQW0dg9JGjuwZcILuNsZQJBAk1MSHz9q4Azr5F3y9gaKyPNJBVpqAyI8acQRoJF
    ioKaum9hlRf3nuXxmSfqv7iXozX6xfrYncjLKbBn/hPhWp8=
    -----END RSA PRIVATE KEY-----''')

The public key is accessible via the `public` attribute, and the encoded version of a key is available via the `as_string` method.

    >>> pub = key.public
    >>> print pub.as_string()
    -----BEGIN PUBLIC KEY-----
    MIGJAoGBC/1XUOvF+EO3nqsLX+LXwckTrH9IuzbG7kgPJLEjTGGZ7xTpPrASyzbvkxpx1AxJmHkw
    mX7xhESvDHrM6KUPPzLYYOoquy4yACh2S98oB5CVBmn4g9l0mVGGgTUuT9ocE6KpEZHvku5+JMBt
    oMwbc1YzVKJ0T2pVm/cexYmpBTvLAgMBAAE=
    -----END PUBLIC KEY-----

You can see how large a payload a given key/padding/hash will support via the `max_payload` method of a `Key`:

    >>> key.max_payload() # using defaults
    86
    >>> key.max_payload(padding='none')
    128

The reverse is also possible; calculating the key size required for a message payload of at least a given size:

    >>> rsa.key_size_for_payload(100) # using defaults
    1136
    >>> rsa.key_size_for_payload(100, padding='none')
    800

We can encrypt and decrypt:

    >>> msg = b"Hello, World!"
    >>> ct = key.encrypt(msg)
    >>> pt = key.decrypt(ct)
    >>> msg == pt
    True

Note that you can encrypt with a public key, but you can't decrypt:

    >>> ct = pub.encrypt(msg)
    >>> pt = pub.decrypt(ct)
    Traceback (most recent call last):
    <snip>
    tomcrypt.LibError: A private PK key is required.

We can also sign/verify signatures:

    >>> msg = b"Hello, World!"
    >>> sig = key.sign(msg)
    >>> key.verify(msg, sig)
    True

Note that you can verify a signature with a public key, but you can't sign:

    >>> pub.verify(msg, sig)
    True
    >>> sig = pub.sign(msg)
    Traceback (most recent call last):
    <snip>
    tomcrypt.LibError: A private PK key is required.



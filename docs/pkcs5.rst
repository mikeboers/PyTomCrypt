PKCS5
=====

::

    >>> from tomcrypt.pkcs5 import pkcs5
    
This module contains a function which performs the pkcs5 password hashing scheme. Arguments are available to specify the iteration count (defaults to 1024), hash algo (defaults to sha256), and the hash length (defaults to the full hash).

    >>> pkcs5(b'password', salt='salt', iteration_count=1024, hash='sha256')
    b'#\x1a\xfb}\xcd.\x86\x0c\xfdX\xab\x137+\xd1,\x920v\xc3Y\x8a\x12\x19`2\x0fo\xec\x8aV\x98'


.. autofunction:: tomcrypt.pkcs5.pkcs5


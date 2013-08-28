PKCS5
=====

::

    >>> from tomcrypt.pkcs5 import pkcs5
    
This module contains a function which performs the pkcs5 password hashing scheme. Arguments are available to specify the iteration count (defaults to 1024), hash algo (defaults to sha256), and the hash length (defaults to the full hash).

.. autofunction:: tomcrypt.pkcs5.pkcs5


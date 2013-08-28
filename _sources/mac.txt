Message Authentication Codes (MACs)
===================================

Overview
--------

::

    >>> from tomcrypt import mac

This module contains a :class:`.MAC` class, and a convenience function for every MAC provided::

    >>> mymac = mac.MAC('hmac', 'sha256', b'secret')
    >>> # OR
    >>> mymac = mac.hmac('sha256', b'secret')

The module also contains a list of the names of all MACS provided, and lists of those which use ciphers or hashes::

    >>> sorted(mac.names)
    ['hmac', 'omac', 'pmac', 'xcbc']
    >>> sorted(mac.hash_macs)
    ['hmac']
    >>> sorted(mac.cipher_macs)
    ['omac', 'pmac', 'xcbc']

The :class:`MAC` will accept either a name or a ``Descriptor`` to specify which hash/cipher algorithm to use::

    >>> mac.hmac('md5', b'secret', b'content').hexdigest()
    '97e5f3684213a40aaaa9ef31f9f4b1a7'
    >>> mac.hmac(hash.md5, b'secret', b'content').hexdigest()
    '97e5f3684213a40aaaa9ef31f9f4b1a7'
    
    >>> mac.pmac('aes', b'0123456789abcdef', b'content').hexdigest()
    '530566cd1c33e874f503b3c3272d0fd4'
    >>> mac.pmac(cipher.aes, b'0123456789abcdef', b'content').hexdigest()
    '530566cd1c33e874f503b3c3272d0fd4'

The rest of the API is similar to the stdlib ``hmac`` (or ``hashlib`` or ``tomcrypt.hash``, etc.), offering ``update``, ``digest``, ``hexdigest``, and ``copy`` methods.


MAC API
-------

.. automodule:: tomcrypt.mac
    :members:

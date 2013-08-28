Symmetric Ciphers
=================

 
Overview
--------

::

    from tomcrypt import cipher

The ``tomcrypt.cipher`` module contains a :class:`~.cipher.Descriptor` class which describes a cipher, and a :class:`.Cipher` class for using a cipher (eg. keys, IVs, etc.). As a convenience there is a pre-made :class:`~.cipher.Descriptor` for every cipher provided.

The module also contains a list of the names of all ciphers provided,
and the modes that they can operate in::
    
    >>> sorted(cipher.names)
    ['aes', 'anubis', 'blowfish', 'cast5', 'des', 'des3', 'kasumi', 'khazad', 'kseed', 'noekeon', 'rc2', 'rc5', 'rc6', 'rijndael', 'saferp', 'twofish', 'xtea']
    >>> sorted(cipher.modes)
    ['cbc', 'cfb', 'ctr', 'ecb', 'f8', 'lrw', 'ofb']
    
We can inspect some of the properties of a cipher via attributes on a :class:`~.cipher.Descriptor` or :class:`.Cipher`::

    >>> cipher.aes.block_size
    16
    >>> cipher.aes.min_key_size
    16
    >>> cipher.aes.max_key_size
    32

:meth:`Descriptor.key_size <tomcrypt.cipher.Descriptor.key_size>` returns the size of the largest key than can be constructed from a string of a given size::

    >>> cipher.aes.key_size(18)
    16

We can construct a :class:`Cipher` object directly (and pass a cipher name via the ``cipher`` kwarg) or, as a shortcut, use an instantiated :class:`Descriptor` as a factory. You can pass a ``key``, ``iv``, ``cipher`` (if calling ``Cipher``; defaults to ``"aes"``), ``mode`` (defaults to ``"ctr"``), ``tweak`` (only for ``"lrw"`` mode), and ``salt_key`` (only for "f8" mode).

::

    >>> encryptor = cipher.Cipher(key=b'0123456789abcdef', iv=b'0123456789abcdef', cipher='aes', mode='ctr')
    >>> # OR
    >>> encryptor = cipher.aes(key=b'0123456789abcdef', iv=b'0123456789abcdef', mode='ctr')

    >>> message = encryptor.encrypt(b'This is a message')
    >>> message
    b'&\x1a\x17\xfb>\xb5\x8e!a\x87u\r\nz\xd4\x02\x94'
    
    >>> decryptor = cipher.aes(key=b'0123456789abcdef', iv=b'0123456789abcdef', mode='ctr')
    >>> decryptor.decrypt(message)
    b'This is a message'

For those modes which support an IV, you can explicitly get and set it via :meth:`Cipher.get_iv <tomcrypt.cipher.Cipher.get_iv>` and :meth:`Cipher.set_iv <tomcrypt.cipher.Cipher.set_iv>` methods.



Descriptor API
--------------

.. autoclass:: tomcrypt.cipher.Descriptor

    .. automethod:: tomcrypt.cipher.Descriptor.__init__
    .. automethod:: tomcrypt.cipher.Descriptor.__call__

    .. autoattribute:: tomcrypt.cipher.Descriptor.name
    .. autoattribute:: tomcrypt.cipher.Descriptor.block_size
    .. autoattribute:: tomcrypt.cipher.Descriptor.default_rounds

    .. autoattribute:: tomcrypt.cipher.Descriptor.max_key_size
    .. autoattribute:: tomcrypt.cipher.Descriptor.min_key_size
    .. automethod:: tomcrypt.cipher.Descriptor.key_size


Cipher API
----------

.. autoclass:: tomcrypt.cipher.Cipher

Basics
^^^^^^

    .. automethod:: tomcrypt.cipher.Cipher.__init__

    .. automethod:: tomcrypt.cipher.Cipher.encrypt
    .. automethod:: tomcrypt.cipher.Cipher.decrypt

Initialization Vectors
^^^^^^^^^^^^^^^^^^^^^^

    .. automethod:: tomcrypt.cipher.Cipher.get_iv
    .. automethod:: tomcrypt.cipher.Cipher.set_iv


EAX-Specific Methods
^^^^^^^^^^^^^^^^^^^^
    .. automethod:: tomcrypt.cipher.Cipher.add_header
    .. automethod:: tomcrypt.cipher.Cipher.done


..
    .. autofunction:: test_library


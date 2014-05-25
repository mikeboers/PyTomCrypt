Hash Functions
==============

Overview
--------

::

    >>> from tomcrypt import hash

This module contains a :class:`~.hash.Descriptor` class which describes a hash, and a :class:`Hash` class for using a hash. As a convenience there is a pre-made :class:`~.hash.Descriptor` for every hash provided::

    >>> hasher = hash.Hash('sha256')
    >>> # OR:
    >>> hasher = hash.sha256()

The module also contains a list of the names of all hashes provided::

    >>> sorted(hash.names)
    ['chc', 'md2', 'md4', 'md5', 'rmd128', 'rmd160', 'rmd256', 'rmd320', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'tiger', 'whirlpool']

The module has been designed to be a drop-in replacement for ``hashlib`` (:func:`~.new` is simply another name for :class:`Hash`)::

    >>> hasher = hash.new('sha256')

You can also provide initial content::

    >>> hasher = hash.Hash('sha256', b'intial')
    >>> # OR:
    >>> hasher = hash.new('sha256', b'intial')
    >>> # OR:
    >>> hasher = hash.sha256(b'intial')

The rest of the API is the same as hashlib as well::

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


Descriptor API
--------------

.. autoclass:: tomcrypt.hash.Descriptor
    :members:


Hasher API
----------

.. autoclass:: tomcrypt.hash.Hash
    :members:

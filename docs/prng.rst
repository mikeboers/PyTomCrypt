Pseudo-Random Number Generators (PRNGs)
=======================================

Overview
--------

::

    >>> from tomcrypt import prng

This module contains a :class:`PRNG` class which contains all state required for a PRNG, and a convenience function for every PRNG provided::

    >>> myrng = prng.PRNG('yarrow')
    >>> # OR
    >>> myrng = prng.yarrow()

The module also contains a list of the names of all PRNGs provided::

    >>> sorted(prng.names)
    ['fortuna', 'rc4', 'sober128', 'sprng', 'yarrow']

You can add entropy via the :meth:`PRNG.add_entropy` method::

    >>> myrng = prng.yarrow()
    >>> myrng.add_entropy('hello')
    >>> myrng.read(8).encode('hex')
    b'f34a113448ead699'

You can use the system PRNG (eg. ``/dev/urandom``) to auto-seed your :class:`PRNG`, either at construction or any time afterwards::

    >>> # Seed with 1024 bytes from system PRNG.
    >>> myrng = prng.yarrow(1024)
    >>> myrng.read(8).encode('hex')
    <will always be different>
    >>> # Add another 1024 bytes from system PRNG.
    >>> myrng.auto_seed(1024)
    >>> myrng.read(8).encode('hex')
    <will always be different>

The system PRNG is also directly available via the same API as the ``"sprng"`` object.


PRNG API
--------

.. automodule:: tomcrypt.prng
    :members:

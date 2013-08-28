RSA
===

Overview
--------

::

    >>> from tomcrypt import rsa

This module contains a :class:`.Key` class for encrypting, decrypting, signing, and verifying data with a RSA private or public key.


Padding
^^^^^^^

By default, encryption will use OAEP_ padding, and signing will use PSS_ padding.

For greater compatibility (e.g. with OpenSSL which does not support PSS padding via the ``openssl rsautl`` command), you can use PKCS1_ padding by setting the keyword argument ``padding="v1.5"`` on many methods. If padding has already been applied, you can also use ``padding="none"`` to disable it entirely.

.. _PKCS1: http://tools.ietf.org/html/rfc2313
.. _OAEP: http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/what-is-oaep.htm
.. _PSS: http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/what-is-pss-pss-r.htm


Hashing
^^^^^^^

By default the keys will use ``sha1`` for part of the encryption padding, and ``sha512`` for the signature, but these can be changed via the ``hash`` keyword arg on many methods.


Use
^^^

You can generate new keys::

    >>> key = rsa.Key(1024)

Or you can load an existing key from a string::

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

The public key is accessible via the :attr:`~.Key.public` attribute, and the encoded version of a key is available via the :meth:`~.Key.as_string` method::

    >>> pub = key.public
    >>> print pub.as_string()
    -----BEGIN PUBLIC KEY-----
    MIGJAoGBC/1XUOvF+EO3nqsLX+LXwckTrH9IuzbG7kgPJLEjTGGZ7xTpPrASyzbvkxpx1AxJmHkw
    mX7xhESvDHrM6KUPPzLYYOoquy4yACh2S98oB5CVBmn4g9l0mVGGgTUuT9ocE6KpEZHvku5+JMBt
    oMwbc1YzVKJ0T2pVm/cexYmpBTvLAgMBAAE=
    -----END PUBLIC KEY-----

You can see how large a payload a given key/padding/hash will support via the :meth:`~.Key.max_payload` method::

    >>> key.max_payload() # using defaults
    86
    >>> key.max_payload(padding='none')
    128

The reverse is also possible; calculating the key size required for a message payload of at least a given size::

    >>> rsa.key_size_for_payload(100) # using defaults
    1136
    >>> rsa.key_size_for_payload(100, padding='none')
    800

We can encrypt and decrypt::

    >>> msg = b"Hello, World!"
    >>> ct = key.encrypt(msg)
    >>> pt = key.decrypt(ct)
    >>> msg == pt
    True

Note that you can encrypt with a public key, but you can't decrypt::

    >>> ct = pub.encrypt(msg)
    >>> pt = pub.decrypt(ct)
    Traceback (most recent call last):
    <snip>
    tomcrypt.LibError: A private PK key is required.

We can also sign/verify signatures::

    >>> msg = b"Hello, World!"
    >>> sig = key.sign(msg)
    >>> key.verify(msg, sig)
    True

Note that you can verify a signature with a public key, but you can't sign::

    >>> pub.verify(msg, sig)
    True
    >>> sig = pub.sign(msg)
    Traceback (most recent call last):
    <snip>
    tomcrypt.LibError: A private PK key is required.


RSA API
-------

.. automodule:: tomcrypt.rsa
    :members:

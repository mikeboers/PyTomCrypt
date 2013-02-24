Symmetric Ciphers
=================

.. automodule:: tomcrypt.cipher
    
    Cipher Descriptors
    ------------------

    .. autoclass:: Descriptor

        .. automethod:: tomcrypt.cipher.Descriptor.__init__
        .. automethod:: tomcrypt.cipher.Descriptor.__call__

        .. autoattribute:: tomcrypt.cipher.Descriptor.name
        .. autoattribute:: tomcrypt.cipher.Descriptor.block_size
        .. autoattribute:: tomcrypt.cipher.Descriptor.default_rounds

        .. autoattribute:: tomcrypt.cipher.Descriptor.max_key_size
        .. autoattribute:: tomcrypt.cipher.Descriptor.min_key_size
        .. automethod:: tomcrypt.cipher.Descriptor.key_size


    Using Ciphers
    -------------

    .. autoclass:: Cipher
    
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


    .. autofunction:: test_library


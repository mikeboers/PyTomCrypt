from tomcrypt._core cimport *
from tomcrypt._core import Error


def test_library():
    """Run internal libtomcrypt cipher tests.
    
    >>> test_library()
    True
    
    """
    
    % for name in cipher_names:
    % if not name.endswith('_enc'):
    check_for_error(${name}_test())
    % endif
    % endfor
    check_for_error(eax_test())
    return True
        

# Register all the ciphers.
cdef int max_cipher_idx = -1
% for name in cipher_names:
max_cipher_idx = max(max_cipher_idx, register_cipher(&${name}_desc))
% endfor


cdef int get_cipher_idx(object input):
    cdef int idx = -1
    # (unicode, str) is a standin for basestring, which doesn't exist in 3.
    # This line has the effect of accepting only strings in 3, and
    # bytes/strings in 2.
    if isinstance(input, (unicode, str)):
        input = {
            'des3': '3des',
            'kseed': 'seed',
            'rijndael': 'aes', # This one is not cool.
            'saferp': 'safer+',
        }.get(input, input)
        b_input = input.encode()
        idx = find_cipher(b_input)
    elif isinstance(input, Descriptor):
        idx = input.idx
    if idx < 0 or idx > max_cipher_idx:
        raise Error('could not find cipher %r' % input)
    return idx


cdef class Descriptor(object):
    """LibTomCrypt descriptor of a symmetric cipher.
    
    Can be called as convenience to calling Cipher, passing the cipher name
    via kwargs.

    >>> aes = Descriptor('aes') # Same as tomcrypt.cipher.aes.
    
    """
    
    def __init__(self, cipher):
        self.idx = get_cipher_idx(cipher)
        self.desc = &cipher_descriptors[self.idx]
        
    def __repr__(self):
        return ${repr('<%s.%s of %s>')} % (
            self.__class__.__module__, self.__class__.__name__, self.name)
                
    @property
    def name(self):
        """Name of this cipher.

        >>> aes.name
        'aes'

        """
        # The extra str is so that Python 2 will return a byte string.
        return str(self.desc.name.decode())

    @property
    def min_key_size(self):
        """Minimum key size for this cipher, in bytes.

        >>> aes.min_key_size
        16

        """
        return self.desc.min_key_size
    
    @property
    def max_key_size(self):
        """Maximum key size for this cipher, in bytes.

        >>> aes.max_key_size
        32

        """
        return self.desc.max_key_size

    @property
    def block_size(self):
        """Block size of this cipher.

        >>> aes.block_size
        16

        """
        return self.desc.block_size

    @property
    def default_rounds(self):
        """Default number of "rounds" for this cipher.

        >>> aes.default_rounds
        10

        """
        return self.desc.default_rounds

    def key_size(self, key_size):
        """The largest key that can be sliced from a string of the given size.

        >>> aes.key_size(16)
        16
        >>> aes.key_size(17)
        16
        >>> aes.key_size(128)
        32

        """
        cdef int out = key_size
        check_for_error(self.desc.key_size(&out))
        return out
    
    def __call__(self, *args, **kwargs):
        """Initialize a cipher state.

        This is a convenience for constructing Cipher objects.

        >>> cipher = aes(b'0123456789abcdef')
        >>> cipher.encrypt(b'hello')
        b'c\\xfey\\xb6$'
        
        """
        return Cipher(*args, cipher=self.name, **kwargs)


# Define a type to masquarade as ANY of the mode states.
cdef union symmetric_all:
    % for mode in cipher_no_auth_modes:
    symmetric_${mode} ${mode}
    % endfor
    % for mode in cipher_auth_modes:
    ${mode}_state ${mode}
    % endfor


cdef class Cipher(Descriptor):
    """All state required to encrypt/decrypt with a symmetric cipher.
    
    Parameters:
        bytes key -- Symmetric key.
        bytes iv -- Initialization vector; None is treated as all null bytes.
        str cipher -- The name of the cipher to use; defaults to "aes".
        str mode -- Cipher block chaining more to use; defaults to "ctr".
    
    Mode Specific Parameters:
        bytes nonce -- Only for "eax" mode.
        bytes tweak -- Only for "lrw" mode.
        bytes salt_key -- Only for "f8" mode.

    >>> cipher = Cipher(b'0123456789abcdef', b'0123456789abcdef', 'aes', 'cbc')

    See Cipher.add_header(...) for example of EAX mode.

    """
    
    cdef symmetric_all state
    cdef readonly object mode
    cdef int mode_i
    
    def __init__(self, bytes key, bytes iv=None, cipher='aes', mode='ctr', **kwargs):
        self.mode = mode
        ## We must keep these indices as magic numbers in the source.
        self.mode_i = {
        % for mode, i in cipher_mode_items:
            ${repr(mode)}: ${i},
        % endfor
        }.get(self.mode, -1)
        if self.mode_i < 0:
            raise Error('no mode %r' % mode)
        Descriptor.__init__(self, cipher)
        
        # Create null IV.
        if iv is None:
            iv = b'\0' * self.desc.block_size
        if not isinstance(iv, bytes) or len(iv) != self.desc.block_size:
            raise Error('iv must be %d bytes; got %r' % (self.desc.block_size, iv))
        
        # Initialize the various modes.
        % for mode, i in cipher_mode_items:
        ${'el' if i else ''}if self.mode_i == ${i}: # ${mode}

            % if mode == 'ecb':
            check_for_error(ecb_start(self.idx, key, len(key), 0, <symmetric_${mode}*>&self.state))
            
            % elif mode == 'ctr':
            check_for_error(ctr_start(self.idx, iv, key, len(key), 0, CTR_COUNTER_BIG_ENDIAN, <symmetric_${mode}*>&self.state))
            
            % elif mode in cipher_simple_modes:
            check_for_error(${mode}_start(self.idx, iv, key, len(key), 0, <symmetric_${mode}*>&self.state))
            
            % elif mode == 'lrw':
            tweak = kwargs.get('tweak')
            if not isinstance(tweak, str) or len(tweak) != 16:
                raise Error('tweak must be 16 byte string')
            check_for_error(${mode}_start(self.idx, iv, key, len(key), tweak, 0, <symmetric_${mode}*>&self.state))
            
            % elif mode == 'f8':
            salt_key = kwargs.get('salt_key')
            if not isinstance(salt_key, bytes):
                raise Error('salt_key must be bytes')
            check_for_error(${mode}_start(self.idx, iv, key, len(key), salt_key, len(salt_key), 0, <symmetric_${mode}*>&self.state))
            
            % elif mode == 'eax':
            nonce = kwargs.get('nonce', iv)
            if not isinstance(nonce, bytes):
                raise Error('nonce must be bytes')
            header = kwargs.get('header', b'')
            if not isinstance(header, bytes):
                raise Error('header must be bytes')
            check_for_error(eax_init(<eax_state*>&self.state, self.idx,
                key, len(key),
                nonce, len(nonce),
                header, len(header),
            ))

            % else:
            raise Error('no start for mode %r' % ${repr(mode)})
            
            % endif
        % endfor

    def __repr__(self):
        return ${repr('<%s.%s with %s in %s mode at 0x%x>')} % (
            self.__class__.__module__, self.__class__.__name__, self.name,
            self.mode, id(self))
    
    cpdef get_iv(self):
        """Returns the current IV, for modes that use it.

        >>> cipher = aes(b'0123456789abcdef', b'ThisWillSetTheIV')
        >>> cipher.get_iv()
        b'ThisWillSetTheIV'

        >>> cipher = aes(b'0123456789abcdef', mode='ecb')
        >>> cipher.get_iv()
        Traceback (most recent call last):
        ...
        tomcrypt.Error: 'ecb' mode does not use an IV
        
        """
        cdef unsigned long length
        length = self.desc.block_size
        iv = PyBytes_FromStringAndSize(NULL, length)
        % for i, (mode, mode_i) in enumerate(sorted(cipher_iv_modes.items())):
        ${'el' if i else ''}if self.mode_i == ${mode_i}: # ${mode}
            check_for_error(${mode}_getiv(iv, &length, <symmetric_${mode}*>&self.state))
        % endfor
        else:
            raise Error('%r mode does not use an IV' % self.mode)
        return iv
    
    cpdef set_iv(self, iv):
        """ Sets the current IV, for modes that use it.

        See the LibTomCrypt manual section 3.4.6 for what, precisely, this
        function will do depending on the chaining mode.

        >>> cipher = aes(b'0123456789abcdef')
        >>> cipher.set_iv(b'ThisWillSetTheIV')
        >>> cipher.encrypt(b'hello')
        b'\\xe2\\xef\\xc5\\xe6\\x9e'

        >>> cipher = aes(b'0123456789abcdef', mode='ecb')
        >>> cipher.set_iv(b'does not matter')
        Traceback (most recent call last):
        ...
        tomcrypt.Error: 'ecb' mode does not use an IV

        """
        % for i, (mode, mode_i) in enumerate(sorted(cipher_iv_modes.items())):
        ${'el' if i else ''}if self.mode_i == ${mode_i}: # ${mode}
            check_for_error(${mode}_setiv(iv, len(iv), <symmetric_${mode}*>&self.state))
        % endfor
        else:
            raise Error('%r mode does not use an IV' % self.mode)
    
    cpdef add_header(self, bytes header):
        """Add the given string to the EAX header. Only for EAX mode.

        >>> cipher = aes(b'0123456789abcdef', mode='eax', nonce=b'random')
        >>> cipher.add_header(b'a header')
        >>> cipher.encrypt(b'hello')
        b'Y\\x9b\\xe5\\x87\\xcc'
        >>> cipher.done()
        b'A(|\\x9f@I#\\x0f\\x93\\x90Z,\\xb5A\\x9bN'

        >>> cipher = aes(b'0123456789abcdef', mode='eax', nonce=b'random', header=b'a header')
        >>> cipher.decrypt(b'Y\\x9b\\xe5\\x87\\xcc')
        b'hello'
        >>> cipher.done()
        b'A(|\\x9f@I#\\x0f\\x93\\x90Z,\\xb5A\\x9bN'

        """
        if self.mode_i != ${repr(cipher_modes['eax'])}:
            raise Error('only for EAX mode')
        check_for_error(eax_addheader(<eax_state*>&self.state, header,
            len(header)))

    % for type in 'encrypt decrypt'.split():
    cpdef ${type}(self, bytes input):
        """${type.capitalize()} a string.
        
        % if type == 'encrypt':
        >>> cipher = aes(b'0123456789abcdef')
        >>> cipher.encrypt(b'this is a message')
        b'\\x7f\\xf3|\\xa9k-\\xd3\\xd5t=\\xa2\\xa1\\xb3lT\\xb2d'

        % else:
        >>> cipher = aes(b'0123456789abcdef')
        >>> cipher.decrypt(b'\\x7f\\xf3|\\xa9k-\\xd3\\xd5t=\\xa2\\xa1\\xb3lT\\xb2d')
        b'this is a message'

        % endif
        """
        cdef int length
        length = len(input)
        # We need to make sure we have a brand new string as it is going to be
        # modified. The input will not be, so we can use the python one.
        output = PyBytes_FromStringAndSize(NULL, length)
        % for mode, i in cipher_mode_items:
        ${'el' if i else ''}if self.mode_i == ${i}: # ${mode}
            % if mode in cipher_auth_modes:
            check_for_error(${mode}_${type}(<${mode}_state*>&self.state, input, output, length))
            % else:
            check_for_error(${mode}_${type}(input, output, length, <symmetric_${mode}*>&self.state))
            % endif
        % endfor
        return output
    
    % endfor

    cpdef done(self):
        """Return authentication tag for EAX mode.

        See Cipher.add_header(...) for example.

        """
        cdef unsigned long length = 1024

        if self.mode_i == ${repr(cipher_modes['eax'])}:
            output = PyBytes_FromStringAndSize(NULL, length)
            check_for_error(eax_done(<eax_state*>&self.state, output, &length))
            return output[:length]
        else:
            raise Error('not for %s mode' % self.mode)


names = ${repr(set(cipher_names))}
modes = ${repr(set(cipher_modes.keys()))}

% for name in cipher_names:
${name} = Descriptor(${repr(name)})
% endfor


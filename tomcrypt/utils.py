from __future__ import print_function

import re
import base64

from . import Error

def pem_encode(type, mode, content):
    """PEM encode a key.

    :param str type: ``"RSA"``, ``"EC"``, etc.
    :param str mode: ``"PUBLIC"`` or ``"PRIVATE"``
    :param bytes content: The content to encode.

    >>> print(pem_encode('TEST', 'PRIVATE', b'private content'))
    -----BEGIN TEST PRIVATE KEY-----
    cHJpdmF0ZSBjb250ZW50
    -----END TEST PRIVATE KEY-----

    >>> print(pem_encode('TEST', 'PUBLIC', b'public content'))
    -----BEGIN PUBLIC KEY-----
    cHVibGljIGNvbnRlbnQ=
    -----END PUBLIC KEY-----

    """

    type = type.upper()
    mode = mode.upper()
    if mode not in ('PUBLIC', 'PRIVATE'):
        raise Error('mode must be PUBLIC or PRIVATE')
    type = ('%s %s' % (type, mode)) if mode == 'PRIVATE' else 'PUBLIC'
    content = str(base64.b64encode(content).decode())
    content = '\n'.join(content[i:i+78] for i in range(0, len(content), 78))
    return '-----BEGIN %(type)s KEY-----\n%(content)s\n-----END %(type)s KEY-----\n' % dict(
        type=type,
        content=content,
    )

_pem_re = re.compile(r"""
    ^\s*
    -----BEGIN\ (([A-Z]+\ )?(PUBLIC|PRIVATE))\ KEY-----
    (.+)
    -----END\ \1\ KEY-----
    \s*$
""", re.VERBOSE | re.DOTALL)


def pem_decode(content):
    """PEM decode a key.

    Returns a tuple of:
    
    - type: E.g. ``"RSA"``, ``"EC"``, or None (likely if public);
    - mode: ``"PRIVATE"`` or ``"PUBLIC"``;
    - content: original content.

    Throws a tomcrypt.Error if content is not PEM encoded.

    """

    m = _pem_re.match(content)
    if not m:
        raise Error('not PEM encoded')
    type, mode, content = m.group(2, 3, 4)
    type = type and type.rstrip().upper()
    mode = mode.upper()
    content = base64.b64decode(''.join(content.strip().split()).encode())
    return type, mode, content



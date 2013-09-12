import base64
import doctest
import errno
import hashlib
import os
import sys
import time
from base64 import b64encode, b64decode
from pprint import pprint, pformat
from subprocess import Popen, PIPE, check_call
from unittest import TestCase as BaseTestCase


is_py3 = sys.version_info[0] >= 3


sandbox = os.path.join(
    os.path.dirname(__file__),
    'sandbox',
)


b16encode = lambda x: base64.b16encode(x).lower()
b16decode = lambda x, casefold=True: base64.b16decode(x, casefold)


def fix_doctests(suite):
    for case in suite._tests:

        # Add some more flags.
        case._dt_optionflags = (
            (case._dt_optionflags or 0) |
            doctest.IGNORE_EXCEPTION_DETAIL |
            doctest.ELLIPSIS |
            doctest.NORMALIZE_WHITESPACE
        )

        if sys.version_info[0] >= 3:
            continue
        
        # Remove b prefix from strings.
        for example in case._dt_test.examples:
            if example.want.startswith("b'"):
                example.want = example.want[1:]


def get_doctests(mod):
    suite = doctest.DocTestSuite(mod)
    fix_doctests(suite)
    return suite


class TestCase(BaseTestCase):

    @property
    def full_name(self):
        
        try:
            return self._full_name
        except AttributeError:
            pass
        
        module = sys.modules.get(self.__class__.__module__)
        if module and module.__file__:
            file_name = os.path.basename(os.path.splitext(module.__file__)[0])
        else:
            file_name = 'unknown'
        
        self._full_name = file_name + '.' + self.__class__.__name__
        return self._full_name
        
    @property
    def sandbox(self):
        path = os.path.join(sandbox, self.full_name)
        try:
            os.makedirs(path)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        return path


from __future__ import division

from . import *

from tomcrypt import utils
from tomcrypt.utils import *


def load_tests(loader, tests, ignore):
    tests.addTests(get_doctests(utils))
    return tests


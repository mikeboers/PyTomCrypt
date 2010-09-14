from __future__ import division

import os
import hashlib

from tomcrypt.hash import *


def test_against_hashlib():
    for name in hash_names:
        if name == 'chc':
            continue
        try:
            y = hashlib.new(name)
        except ValueError:
            continue
        yield check_hashlib, name

def check_hashlib(name):        
    x = Hash(name)
    y = hashlib.new(name)
    for i in xrange(100):
        s = os.urandom(i)
        x.update(s)
        y.update(s)
        assert x.digest() == y.digest()
    x2 = x.copy()
    x2.update('something else')
    assert x.digest() == y.digest()
    assert x2.digest() != y.digest()

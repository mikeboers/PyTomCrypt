
from __future__ import division

import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import time
from subprocess import Popen, PIPE
import hashlib

from tomcrypt.hash import *


def test_hashlib():
	for name in hashes:
		if name == 'chc':
			continue
		print name, 
		x = Hash(name)
		try:
			y = hashlib.new(name)
		except ValueError:
			print 'is unknown to hashlib'
			continue
		print
		for i in xrange(100):
			s = os.urandom(i)
			x.update(s)
			y.update(s)
			assert x.digest() == y.digest()
		x2 = x.copy()
		x2.update('something else')
		assert x.digest() == y.digest()
		assert x2.digest() != y.digest()
	
if __name__ == '__main__':
	start_time = time.time()
	print 'Running internal tests...'
	test()
	print 'Running against hashlib...'
	test_hashlib()
	print 'Ran all tests in %.2fms' % (1000 * (time.time() - start_time))
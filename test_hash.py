
from __future__ import division

import os
import time
from subprocess import Popen, PIPE
import hashlib

from hash import *


def test_hashlib():
	x = Hash('md5')
	y = hashlib.new('md5')
	for i in xrange(100):
		s = os.urandom(i)
		x.update(s)
		y.update(s)
		assert x.digest() == y.digest()
	
if __name__ == '__main__':
	start_time = time.time()
	print 'Running internal tests...'
	test()
	print 'Running against hashlib...'
	test_hashlib()
	print 'Ran all tests in %.2fms' % (1000 * (time.time() - start_time))
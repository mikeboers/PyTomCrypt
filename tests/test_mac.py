
from __future__ import division

import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import time
from subprocess import Popen, PIPE
import hmac

from tomcrypt import mac
from tomcrypt._main import Error as TomCryptError

def test_py_hmac_oneshot():
	for i in range(1, 10):
		key = os.urandom(8 * i)
		x = hmac.new(key)
		y = mac.hmac(key, hash='md5')
		for j in range(1, 10):
			v = os.urandom(j * 8)
			x.update(v)
			y.update(v)
		assert x.digest() == y.digest()

def test_py_hmac_multi():
	i = j = -1
	try:
		for i in range(1, 10):
			j = -1
			key = os.urandom(8 * i)
			x = hmac.new(key)
			y = mac.hmac(key, hash='md5')
			for j in range(1, 10):
				v = os.urandom(j * 8)
				x.update(v)
				y.update(v)
				assert x.digest() == y.digest()
	except (AssertionError, TomCryptError) as e:
		assert False, 'failed on %d-%d: %r' % (i, j, e)

def test_py_hmac_copy():
	i = j = -1
	try:
		for i in range(1, 10):
			j = -1
			key = os.urandom(8 * i)
			x = mac.hmac(key, hash='md5')
			for j in range(1, 10):
				v = os.urandom(j * 8)
				y = x.copy()
				x.update(v)
				y.update(v)
				assert x.digest() == y.digest()
				d = x.digest()
				y = x.copy()
				y.update(v)
				assert y.digest() != d
				assert x.digest() == d
	except (AssertionError, TomCryptError) as e:
		assert False, 'failed on %d-%d: %r' % (i, j, e)
					
if __name__ == '__main__':
	start_time = time.time()
	print 'Running internal tests...'
	mac.test()
	print 'Running against hmac module...'
	test_py_hmac_oneshot()
	test_py_hmac_multi()
	test_py_hmac_copy()
	print 'Ran all tests in %.2fms' % (1000 * (time.time() - start_time))
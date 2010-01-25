
from __future__ import division

import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import time
from subprocess import Popen, PIPE
import hmac

from tomcrypt import mac


def test_py_hmac():
	for i in range(1, 10):
		key = os.urandom(8 * i)
		x = hmac.new(key)
		y = mac.hmac(key, hash='md5')
		for j in range(1, 10):
			v = os.urandom(j * 8)
			print i, j
			x.update(v)
			y.update(v)
			assert x.hexdigest() == y.hexdigest()
	
if __name__ == '__main__':
	start_time = time.time()
	print 'Running internal tests...'
	mac.test()
	print 'Running against hmac module...'
	test_py_hmac()
	print 'Ran all tests in %.2fms' % (1000 * (time.time() - start_time))
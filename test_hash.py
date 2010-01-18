
from __future__ import division

import os
import time
from subprocess import Popen, PIPE

from hash import *


def test_hashlib():
	x = Hash('md5')
	print x

if __name__ == '__main__':
	start_time = time.time()
	print 'Running internal tests...'
	test()
	print 'Running against hashlib...'
	test_hashlib()
	print 'Ran in %.2fms' % (1000 * (time.time() - start_time))
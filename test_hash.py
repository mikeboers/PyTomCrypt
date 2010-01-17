
from __future__ import division

import os
import time
from subprocess import Popen, PIPE

from hash import *




if __name__ == '__main__':
	start_time = time.time()
	print 'Running internal tests...'
	test()
	print 'Ran in %.2fms' % (1000 * (time.time() - start_time))
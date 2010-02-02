
from __future__ import division

import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from pprint import pprint, pformat
import time
from subprocess import Popen, PIPE
import hashlib

from tomcrypt import prng
from tomcrypt.rsa import *
	
if __name__ == '__main__':
	start_time = time.time()
	
	k = Key.generate()
	
	
	# der = k.as_string(type='public')
	# k2 = Key.from_string(der)

	
	k2 = k.public
	print k2, k.public
	print k, k2
	
	print k.as_string()
	print k2.as_string()	
	
	
	print 'Ran all tests in %.2fms' % (1000 * (time.time() - start_time))
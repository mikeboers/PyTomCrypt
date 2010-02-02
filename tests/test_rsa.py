
from __future__ import division

import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import time
from subprocess import Popen, PIPE
import hashlib

from tomcrypt import prng
from tomcrypt.rsa import *
	
if __name__ == '__main__':
	start_time = time.time()
	
	k = Key.generate()
	k.dump()
	print k.as_dict()
	
	
	
	print 'Ran all tests in %.2fms' % (1000 * (time.time() - start_time))
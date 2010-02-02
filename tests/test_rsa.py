
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
	k.dump()
	pprint(k.as_dict())
	der = k.as_string(type='public')
	
	k2 = Key.from_string(der)
	pprint(k2.as_dict())
	
	
	print 'Ran all tests in %.2fms' % (1000 * (time.time() - start_time))
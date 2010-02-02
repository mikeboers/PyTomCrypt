
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
	
	private = Key.from_string('''-----BEGIN RSA PRIVATE KEY-----
    MIICXQIBAAKBgQC9mcyIFoka73NeECWjCHxr5ssMU5MBPpV2AMYHmtB8qiO5gmiU
    qVjSZGdtHUAUdzigQsguKmihSaJGBctUPwdRaQY+CGj2zkIj+yEWPb/ieGAtA5XP
    YDPzhc43SY//N8dlFme4s3zjjNrUcuMhy4hsmv4p35DXKfa6sB0V5EXVzwIDAQAB
    AoGAOoO2zeE2myt/TW5qTzCVRa/Kxpkca2vnMK34b+xln7PapqwKnqbNFNGL4e7/
    EdHhlgRGR4krFWvmOvoa0HtLRFrFI64+XdbrZpA8tMwzZa5tmOQwDTwJzClcSXqt
    ySuQsH2l05UT21UNpDn7Ph4PlswLUQvYkI9EPTxgWOcDkLECQQDgNtwQoVonMVIv
    nt7qt3d2XmiKgjEJwsgNt4EkriM0FCNByslVs+KFCOw331bHcvMOMULTp0imIZ/t
    XvtmB6jdAkEA2HrAn+ObrKT2mySXjnezGqv8sq3jmHKiruNDTslBlQ4ByC4LWiWl
    3Q1ncBraUHwwHm4dAExTnI3W4t8Lyzd4mwJBAJKqkC24vnZgxvgrnno/ZT/i5dOk
    8lsGNULzxOCvoIuSmLWS5zzOnOCVQ6AQ0n1JbkDcbHBzPwyddjYaKa1GWWkCQQDB
    itXm3VbUPtRgFpINhMUzZmrR0Re3t13tYDBQIy0oN1Kuh0QM/7XP8Wj2WHuxE6bt
    veLd3l+uiz2ArovbzydbAkBZlPsjsC1xPy/7tDQ+Rmz4liTrp3w9amOuzD+PQ6RW
    ejD79LHvSb4Kn+p1+ZpYfB7AwAZh/a15auqCBVI9jeBl
    -----END RSA PRIVATE KEY-----
    ''')
	
	public = Key.from_string('''-----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9mcyIFoka73NeECWjCHxr5ssM
    U5MBPpV2AMYHmtB8qiO5gmiUqVjSZGdtHUAUdzigQsguKmihSaJGBctUPwdRaQY+
    CGj2zkIj+yEWPb/ieGAtA5XPYDPzhc43SY//N8dlFme4s3zjjNrUcuMhy4hsmv4p
    35DXKfa6sB0V5EXVzwIDAQAB
    -----END PUBLIC KEY-----
    ''')
		
	pt = 'Hello, world.'
	ct = public.encrypt(pt)
	print repr(ct)
	pt2 = private.decrypt(ct)
	
	print repr(pt2)
	
	sig = private.sign(pt)
	print repr(sig)
	print public.verify(pt, sig)
	print public.verify(pt + '1', sig)
	print public.verify(pt, sig + '1')
	
	print 'Ran all tests in %.2fms' % (1000 * (time.time() - start_time))
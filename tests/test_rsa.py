
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
	
	size = key_size_for_payload(100)
	k = generate_key(size)
	print size, k.size
	print 100, k.max_payload()
	
	key = Key('''-----BEGIN RSA PRIVATE KEY-----
    MIICXwIBAAKBgQv9V1DrxfhDt56rC1/i18HJE6x/SLs2xu5IDySxI0xhme8U6T6w
    Ess275MacdQMSZh5MJl+8YRErwx6zOilDz8y2GDqKrsuMgAodkvfKAeQlQZp+IPZ
    dJlRhoE1Lk/aHBOiqRGR75LufiTAbaDMG3NWM1SidE9qVZv3HsWJqQU7ywIDAQAB
    AoGBBbw8ppMCco5CKf58RHQI7cQ4Sw3gRt4fLyD9TXoG/qS5tCp2oOwtMVSoKeA+
    j0cJdYyTePnGopUQf5HGr4s1zew14Ks2/91J70MEiABvrvVv9ZfiLT1e9/U/HdYE
    s9Vv4NOpStZHhTcUrQXtiEBG+8VQhCIeuW1J9XKT8gTa7A+xAkED/rTemeSV9hQa
    r9gJ4IHWVgJSNMm4A3bWsEM2R9Dm0Iwif8R/RHHJrsHgTKukYOOwbW7RFHwh+QVU
    fL4pXjVR9wJBAwBORpdlEgWAD4IQK0CR6w3htz7w3KrS6OuckEPItA+W9Edt1n/a
    v8Q7FiIdoHWPI4qaCI1g1GlOCUyXtaJb780CQQDKdafzs0r0sjouQYiDB3EVCdSY
    Wq6xEN+jeUrPoM1wz60suguv0w7oJ71tsDUUcT7GC0Ac3A4lrCZzo3mxCsE1AkEA
    419G7tj/a1dJv6EPW82TNYl+FIdtlrRSMCAmZZkJCLAQ3O65kx7mr6kY1MHV0dSp
    nQQW0dg9JGjuwZcILuNsZQJBAk1MSHz9q4Azr5F3y9gaKyPNJBVpqAyI8acQRoJF
    ioKaum9hlRf3nuXxmSfqv7iXozX6xfrYncjLKbBn/hPhWp8=
    -----END RSA PRIVATE KEY-----''')
    
	print '1028?', key.size
	print key.encrypt('hello').encode('base64')
    
	private = Key('''-----BEGIN RSA PRIVATE KEY-----
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
	
	public = Key('''-----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9mcyIFoka73NeECWjCHxr5ssM
    U5MBPpV2AMYHmtB8qiO5gmiUqVjSZGdtHUAUdzigQsguKmihSaJGBctUPwdRaQY+
    CGj2zkIj+yEWPb/ieGAtA5XPYDPzhc43SY//N8dlFme4s3zjjNrUcuMhy4hsmv4p
    35DXKfa6sB0V5EXVzwIDAQAB
    -----END PUBLIC KEY-----
    ''')
	
	print 'max_payload', private.max_payload(), public.max_payload()
	
	pt = 'Hello, world.'
	ct = public.encrypt(pt)
	print 'ct len', len(ct)
	pt2 = private.decrypt(ct)
	
	print repr(pt2)
	
	pt = pt * 1000
	sig = private.sign(pt)
	print repr(sig)
	print public.verify(pt, sig)
	
	print 'bad - pre'
	bad = Key('bad')
	print 'bad - post'
	
	print 'Ran all tests in %.2fms' % (1000 * (time.time() - start_time))
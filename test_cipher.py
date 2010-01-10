
import os
import time

from cipher import *


internal_tests = (
    ( 16,
      ( 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f ), 
      ( 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff ),
      ( 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a )
    ), ( 
      24,
      ( 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 ),
      ( 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff ),
      ( 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 )
    ), (
      32,
      ( 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f ),
      ( 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff ),
      ( 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 )
    )
)


def test_internal():
	for keysize, key, pt, ct in internal_tests:
		key = ''.join(map(chr, key))
		pt = ''.join(map(chr, pt))
		ct = ''.join(map(chr, ct))
		
		cipher = Cipher(key=key, cipher='aes', mode='ecb')
		test_ct = cipher.encrypt(pt)
		assert ct == test_ct, 'internal encrypt: %s != %s' % (ct.encode('hex'), test_ct.encode('hex'))
		cipher = Cipher(key=key, cipher='aes', mode='ecb')
		test_pt = cipher.decrypt(ct)
		assert pt == test_pt, 'internal decrypt: %s != %s' % (pt.encode('hex'), test_pt.encode('hex'))

def test_speed():
	cipher = Cipher('0123456789abcdef', mode='ecb')
	start_time = time.time()
	txt = '0123456789abcdef'
	for i in xrange(50000):
		txt = cipher.encrypt(txt)
	for i in xrange(50000):
		txt = cipher.decrypt(txt)
	assert txt == '0123456789abcdef', 'speed test is wrong: %r' % txt
	print 'Ran in %.2fps' % (10000 * (time.time() - start_time))
		


def test_external():

	for filename in os.listdir('test_vectors'):
		if 'CFB1' in filename:
			continue
		mode = filename[:3].lower()
		fh = open('test_vectors/' + filename, 'rb')
		type = fh.readline().strip()[1:-1].lower()
		fh.readline()

		# print mode, type, filename
		data = {}
		for line in fh:
			line = line.strip()
			if not line and data:
				# print mode, type, data['count']
				# for k in 'iv', 'key', 'plaintext', 'ciphertext':
				# 	if k in data:
				# 		print '\t%3s: %s' % (k, data.get(k))
				key = data['key'].decode('hex')
				iv  = data.get('iv', '').decode('hex')
				pt  = data['plaintext'].decode('hex')
				ct  = data['ciphertext'].decode('hex')
				cipher = Cipher(key=key, iv=iv, cipher='aes', mode=mode)
				if type == 'encrypt':
					res = cipher.encrypt(pt)
					assert res == ct, '%s #%s: %s != %s' % (name, data['count'], res.encode('hex'), data['ciphertext'])
				data = {}
			if ' = ' not in line:
				continue
			k, v = line.lower().split(' = ')
			data[k] = v


if __name__ == '__main__':
	start_time = time.time()
	print 'Running internal tests...'
	test()
	print 'Running cython tests...'
	test_internal()
	print 'Running external tests...'
	test_external()
	print 'Ran in %.2fms' % (1000 * (time.time() - start_time))
	print 'Running speed test...'
	test_speed()
	
	print dir()
	for i in range(AES.min_key_length, AES.max_key_length + 1):
		print AES.keysize(i)
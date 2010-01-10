
from base64 import b64encode
import os

from _cipher import *

_Cipher = Cipher
class Cipher(_Cipher):
	def __init__(self, key, iv='', cipher='aes', mode='cbc'):
		_Cipher.__init__(self, key, iv, cipher, mode)
		try:
			self.encrypt = getattr(self, mode + '_encrypt')
			self.decrypt = getattr(self, mode + '_decrypt')
		except:
			raise ValueError('no mode %r' % mode)

def test():
	for mode in 'ecb', 'cbc':
		for type in 'encrypt', 'decrypt':
			filename = './test_vectors/%s_%s_m.txt' % (mode, type[0])
			fh = open(filename, 'rb')
			lines = fh.readlines()[15:]
			data = {}
			for line in lines:
				line = line.strip()
				if not line and data:
					print mode, type, data['i']
					for k in 'iv', 'pt', 'ct':
						if k in data:
							print '\t%s: %s' % (k, data.get(k))
					key = data['key'].decode('hex')
					iv  = data.get('iv', '').decode('hex')
					pt  = data['pt'].decode('hex')
					ct  = data['ct'].decode('hex')
					cipher = Cipher(key=key, iv=iv, cipher='aes', mode=mode)
					if type == 'encrypt':
						res = cipher.encrypt(pt)
						assert res == ct, '%s != %s' % (res.encode('hex'), data['ct'])
					data = {}
				if line.count('=') != 1:
					continue
				k, v = line.lower().split('=')
				data[k] = v
				

if __name__ == '__main__':
		
	key = '0123456789abcdef'
	for mode in modes:
		cipher = Cipher(key, cipher='aes')
		enc = getattr(cipher, mode + '_encrypt')('0123456789abcdef')
		try:
			iv = getattr(cipher, mode + '_get_iv')()
		except AttributeError:
			iv = ''
		cipher = Cipher(key, cipher='aes')
		dec = getattr(cipher, mode + '_decrypt')(enc)
		print mode, dec, enc.encode('hex'), iv.encode('hex')
	
	print
	test()
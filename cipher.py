


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




if __name__ == '__main__':
		
	key = '0123456789abcdef'
	for mode in modes:
		cipher = Cipher(key, cipher='aes')
		enc = getattr(cipher, mode + '_encrypt')(key)
		try:
			iv = getattr(cipher, mode + '_get_iv')()
		except AttributeError:
			iv = ''
		cipher = Cipher(key, cipher='aes')
		dec = getattr(cipher, mode + '_decrypt')(enc)
		print mode, dec, enc.encode('hex'), iv.encode('hex')
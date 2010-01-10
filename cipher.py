


from base64 import b64encode
import os

from _cipher import *


if __name__ == '__main__':
		
	key = '0123456789abcdef'
	for mode in modes:
		cipher = Cipher(key, cipher='aes', mode=mode)
		enc = cipher.encrypt(key)
		try:
			iv = getattr(cipher, mode + '_get_iv')()
		except AttributeError:
			iv = ''
		cipher = Cipher(key, cipher='aes', mode=mode)
		dec = cipher.decrypt(enc)
		print mode, dec, enc.encode('hex'), iv.encode('hex')
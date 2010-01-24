
ALL_CIPHERS = False

modes = dict((k, i) for i, k in enumerate('ecb cbc ctr cfb ofb lrw f8'.split()))
no_iv_modes = dict((k, modes[k]) for k in 'ecb'.split())
iv_modes = dict((k, modes[k]) for k in modes if k not in no_iv_modes)
simple_modes = dict((k, modes[k]) for k in 'cbc cfb ofb'.split())

mode_items = list(sorted(modes.items(), key=lambda x: x[1]))

if ALL_CIPHERS:
	ciphers = tuple('''
		aes
		anubis
		blowfish
		cast5
		des
		des3
		kasumi
		khazad
		kseed
		noekeon
		rc2
		rc5
		rc6
		saferp
		twofish
		xtea'''.strip().split())
else:
	ciphers = tuple('''
		aes
		blowfish
		des'''.strip().split())



import os
DO_HMAC = 'PyTomCrypt_do_hmac' in os.environ
DO_HASH = not DO_HMAC
class_name = 'Hash' if DO_HASH else 'HMAC'
type = class_name.lower()


hashes = '''
md2
md4
md5
rmd128
rmd160
rmd256
rmd320
sha1
sha224
sha256
sha384
sha512
tiger
whirlpool

'''.strip().split()


import os

ALL_CIPHERS = False

cipher_modes = dict((k, i) for i, k in enumerate('ecb cbc ctr cfb ofb lrw f8'.split()))
cipher_no_iv_modes = dict((k, cipher_modes[k]) for k in 'ecb'.split())
cipher_iv_modes = dict((k, cipher_modes[k]) for k in cipher_modes if k not in cipher_no_iv_modes)
cipher_simple_modes = dict((k, cipher_modes[k]) for k in 'cbc cfb ofb'.split())

cipher_mode_items = list(sorted(cipher_modes.items(), key=lambda x: x[1]))

if ALL_CIPHERS:
	cipher_names = tuple('''
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
	cipher_names = tuple('''
		aes
		blowfish
		des'''.strip().split())

cipher_properties = 'name min_key_size max_key_size block_size default_rounds'.split()

hash_do_hmac = 'PyTomCrypt_do_hmac' in os.environ
hash_do_hash = not hash_do_hmac
hash_class_name = 'Hash' if hash_do_hash else 'HMAC'
hash_type = hash_class_name.lower()


hash_names = '''
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

hash_properties = ('name', 'digest_size', 'block_size')
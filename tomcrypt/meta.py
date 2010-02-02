
# For each actual extension, what are the base names that are included into it?
ext_includes = {
	'_main': 'common cipher hash mac pkcs5 prng rsa'.split()
}




EASY_MODE = True


### CIPHERS

if EASY_MODE:
	raw_cipher_modes = 'ecb cbc ctr'.split()
else:
	raw_cipher_modes = 'ecb cbc ctr cfb ofb lrw f8'.split()

cipher_modes        = dict((k, i) for i, k in enumerate(raw_cipher_modes))
cipher_no_iv_modes  = dict((k, cipher_modes[k]) for k in 'ecb'.split() if k in cipher_modes)
cipher_iv_modes     = dict((k, cipher_modes[k]) for k in cipher_modes if k in cipher_modes and k not in cipher_no_iv_modes)
cipher_simple_modes = dict((k, cipher_modes[k]) for k in 'cbc cfb ofb'.split() if k in cipher_modes)

cipher_mode_items = list(sorted(cipher_modes.items(), key=lambda x: x[1]))

if EASY_MODE:
	cipher_names = tuple('''
		aes
		blowfish
		cast5
		des'''.strip().split())
else:
	cipher_names = tuple('''
		aes
		aes_enc
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
		rijndael
		rijndael_enc
		saferp
		twofish
		xtea
		'''.strip().split())

cipher_properties = 'name min_key_size max_key_size block_size default_rounds'.split()







if EASY_MODE:
	hash_names = '''
		md5
		sha1
		sha224
		sha256
		sha384
		sha512
		'''.strip().split()
else:
	hash_names = '''
		chc
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







if EASY_MODE:
	mac_names = '''
		hmac
		omac
		'''.strip().split()
else:
	mac_names = '''
		hmac
		omac
		pmac
		xcbc
		'''.strip().split()

mac_items = [(name, i) for i, name in enumerate(mac_names)]
mac_ids = dict(mac_items)

hash_macs = set('hmac'.split())
cipher_macs = set(x for x in mac_names if x not in hash_macs)

if EASY_MODE:
	prng_names = """
		sprng
		yarrow
		""".strip().split()
else:
	prng_names = """
		fortuna
		rc4
		sober128
		sprng
		yarrow
		""".strip().split()






cipher_modes = dict((k, i) for i, k in enumerate('ecb cbc ctr cfb ofb lrw f8 eax'.split()))

cipher_no_iv_modes = dict((k, cipher_modes[k]) for k in 'ecb eax'.split())
cipher_iv_modes = dict((k, cipher_modes[k]) for k in cipher_modes if k not in cipher_no_iv_modes)

# "Simple" modes which all have the same interface.
cipher_simple_modes = dict((k, cipher_modes[k]) for k in 'cbc cfb ofb'.split())

cipher_auth_modes = dict((k, cipher_modes[k]) for k in 'eax'.split())
cipher_no_auth_modes = dict((k, cipher_modes[k]) for k in cipher_modes if k not in cipher_auth_modes)

cipher_mode_items = list(sorted(cipher_modes.items(), key=lambda x: x[1]))

if True:
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
		rijndael
		saferp
		twofish
		xtea
	'''.strip().split())
else:
	cipher_names = tuple('''
		aes
		blowfish
		des
	'''.strip().split())

cipher_properties = 'name min_key_size max_key_size block_size default_rounds'.split()



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

# There is no YARROW in here
prng_names = """

	fortuna
	rc4
	sober128
	sprng
	yarrow

""".strip().split()

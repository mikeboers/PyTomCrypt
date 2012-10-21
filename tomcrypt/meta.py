import sys


#: The full name of the compiled module. This is different for Python 2 and 3
#: to facilitate easier testing without recompiling.
module_name = 'tomcrypt._libtomcrypt%d' % (sys.version_info[0])

#: All of the availible cipher modes.
cipher_modes = set('ecb cbc ctr cfb ofb lrw f8 eax'.split())

#: The cipher modes which support IVs.
cipher_iv_modes = set(m for m in cipher_modes if m not in ('ecb', 'eax'))

# The cipher modes which all have the same interface.
cipher_simple_modes = set('cbc cfb ofb'.split())


#: The names of the availible ciphers.
cipher_names = tuple('''
	anubis
	blowfish
	cast5
	des
	3des
	kasumi
	khazad
	seed
	noekeon
	rc2
	rc5
	rc6
	rijndael
	safer+
	twofish
	xtea
'''.strip().split())


#: Mapping cipher names to what is used for as a variable iff the original name
#: is not a valid identifier.
cipher_identfier_mapping = {
    '3des': 'des3',
    'safer+': 'saferp',
    'seed': 'kseed',
}




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

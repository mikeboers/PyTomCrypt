
import sys

from ._main import (MAC as _MAC, mac_names, hash_macs, cipher_macs,
	test_mac as test)


self = sys.modules[__name__]


class MAC(_MAC):
	pass


DEFAULT_HASH = 'sha256'
DEFAULT_CIPHER = 'aes'

def make_mac_constructor(name):
	if name in hash_macs:
		def mac_constructor(key, hash=DEFAULT_HASH, input=''):
			return MAC(name, hash, key, input)
	else:
		def mac_constructor(key, cipher=DEFAULT_CIPHER, input=''):
			return MAC(name, cipher, key, input='')
	mac_constructor.__name__ = name
	return mac_constructor

for name in mac_names:
	self.__dict__[name] = make_mac_constructor(name)
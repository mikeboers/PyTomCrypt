
import sys

from ._main import (HashDescriptor as _Descriptor, Hash as _Hash, hash_names as hashes,
	test_hash as test, CHC as _CHC)


self = sys.modules[__name__]


class Descriptor(_Descriptor):
	def __call__(self, *args, **kwargs):
		return Hash(self.name, *args, **kwargs)

class Hash(_Hash):
	pass

class chc(_CHC):
	pass


for name in hashes:
	try:
		self.__dict__[name] = Descriptor(name)
	except ValueError:
		pass


new = Hash
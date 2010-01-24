
import sys

from ._symmetric import (HashDescriptor as Descriptor, Hash, hash_descs,
	test_hash as test)


self = sys.modules[__name__]

self.__dict__.update(hash_descs)

hashes = hash_descs.keys()

del hash_descs

new = Hash
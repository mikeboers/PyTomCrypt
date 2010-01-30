
import sys

from ._main import (PRNG as _PRNG, prng_names, test_prng as test)


self = sys.modules[__name__]


class PRNG(_PRNG):
	pass


def make_prng_constructor(name):
	def prng_constructor(auto_seed=1024):
		return PRNG(name, auto_seed)
	prng_constructor.__name__ = name
	return prng_constructor

for name in prng_names:
	self.__dict__[name] = make_prng_constructor(name)
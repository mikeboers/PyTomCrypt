
import sys

from . import _main


self = sys.modules[__name__]

for k in dir(_main):
    if k.lower().startswith('rsa_'):
        setattr(self, k[4:], getattr(_main, k))


class Key(_main.RSAKey):
    
    def __repr__(self):
        return '<%s.%s(%s) at 0x%x>' % (self.__class__.__module__, 
            self.__class__.__name__,
            'public' if self.is_public else 'private',id(self))


generate_key = Key.generate
key_from_string = Key.from_string


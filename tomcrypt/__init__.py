
import ctypes


class Error(ValueError):
    def __init__(self, *args, **kwargs):
        self.code = kwargs.get('code', -1)
        ValueError.__init__(self, *args)

class LibError(Error):
    pass


# We need to manually load the _core the first time so that we can specify
# that it use the RTLD_GLOBAL flag. Otherwise (when not on a Mac) the runtime
# linker will not be able to resolve undefined symbols in the other modules.
# This must also be done after the above exceptions are defined so that they
# are availible to the core.
from . import _core
ctypes.PyDLL(_core.__file__, mode=ctypes.RTLD_GLOBAL)

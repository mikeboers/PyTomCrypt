
import os
import ctypes

# We need to manually load the _core SO the first time so that we can specify
# that it use the RTLD_GLOBAL flag. Otherwise (when not on a Mac) the runtime
# linker will not be able to resolve undefined symbols in the other modules.
_core_handle = ctypes.CDLL(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '_core.so'),
    ctypes.RTLD_GLOBAL
)


class Error(ValueError):
    def __init__(self, *args, **kwargs):
        self.code = kwargs.get('code', -1)
        ValueError.__init__(self, *args)

class LibError(Error):
    pass
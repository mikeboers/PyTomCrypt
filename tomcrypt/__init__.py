
class Error(ValueError):
    def __init__(self, *args, **kwargs):
        self.code = kwargs.get('code', -1)
        ValueError.__init__(self, *args)

class LibError(Error):
    pass

# Just so it gets loaded before anything that depends on it.
import tomcrypt._core
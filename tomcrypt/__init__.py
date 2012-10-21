

class TomCryptError(ValueError):
    def __init__(self, *args, **kwargs):
        self.code = kwargs.get('code', -1)
        ValueError.__init__(self, *args)

class LibTomCryptError(TomCryptError):
    pass

# B/C
Error = TomCryptError
LibError = LibTomCryptError

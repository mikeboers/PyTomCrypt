
class Error(ValueError):
    def __init__(self, *args, **kwargs):
        self.code = kwargs.get('code', -1)
        ValueError.__init__(self, *args)

class LibError(Error):
    pass

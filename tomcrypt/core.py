import ctypes
import functools

from . import meta
from . import Error, LibError


__all__ = ['C', 'LTC', 'standard_errcheck']


# I'm not a huge fan of the ctypes API, so I'm pulling a classic Mike move and
# wrapping it in something that dynamically changes it. I'm sorry in advance to
# any readibility issues this causes (especially since this is designed to
# increase readibility).

class _CTypesWrapper(object):
    
    
    def __getattr__(self, name):
        obj = (getattr(ctypes, name, None) or
               getattr(ctypes, "c_" + name, None)
        )
        if obj is not None:
            setattr(self, name, obj)
        return obj

C = _CTypesWrapper()


class _LTCClass(C.CDLL):
    
    def __init__(self):
        
        # Import the module, and init the ctypes library for it.
        self.pymod = __import__(meta.module_name, fromlist=['c'])
        super(_LTCClass, self).__init__(self.pymod.__file__)
        self._wrapped_functions = {}
    
    def function(self, name, restype=None, *argtypes, **kwargs):
        """Wrap a function from the LTC DLL.
    
        This will only allow function types to be specified once. If only requesting
        by name then it will be asserted that the function was already specified.
    
        :param str name: A name of a function exported from LTC.
        :param restype: A ``ctypes`` type.
        :param *argtypes: ``ctypes`` types.
        :param errcheck: ``True`` to signal default LTC errcheck, otherwise a function.
        :returns: The straight ctypes function.
    
        """
        try:
            func = self._wrapped_functions[name]
        except KeyError:
            pass
        else:
            if restype is not None:
                raise RuntimeError('LTC function %r was already wrapped' % name)
        if restype is None:
            raise RuntimeError('LTC function %r is not already wrapped' % name)
        func = getattr(self, name)
        func.restype = restype
        func.argtypes = argtypes
    
        errcheck = kwargs.get('errcheck')
        if errcheck:
            if errcheck is True:
                errcheck = standard_errcheck
            func.errcheck = errcheck
    
        self._wrapped_functions[name] = func
        return func
    
    def wrapper(self, restype, *argtypes):
        """Decorator for wrapping C functions."""
        def _ltc_wrapper(func):
            c_func = self.function(func.__name__, restype, *argtypes)
            @functools.wraps(func)
            def _wrapped(*args, **kwargs):
                return func(c_func, *args, **kwargs)
            return _wrapped
        return _ltc_wrapper


LTC = _LTCClass()








@LTC.wrapper(C.char_p, C.int)
def error_to_string(func, errno):
    """Convert a LibTomCrypt error code to a string.
    
    ::
        >>> error_to_string(0) # Returns `None`.
        >>> error_to_string(4)
        'Invalid number of rounds for block cipher.'
    
    """
    
    if not errno:
        return
    
    # We need to deal with libtomcrypt not defining this error message.
    if errno == LTC.pymod.CRYPT_PK_INVALID_PADDING:
        return "Invalid padding mode."
    
    # Extra str is for Python 2 to get a native string.
    return str(func(errno).decode())


def standard_errcheck(code):
    if code:
        raise LibError(error_to_string, code=code)
    return code

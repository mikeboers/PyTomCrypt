
#include "Python.h"
#if PY_MAJOR_VERSION < 3
    #define PyBytes_FromStringAndSize PyString_FromStringAndSize
#endif

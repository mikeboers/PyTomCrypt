#include <Python.h>
#include "tomcrypt.h"


// We have no methods.
static PyMethodDef tomcrypt_methods[] = {
    {NULL, NULL, 0, NULL}        /* Sentinel */
};


static void init(PyObject *m) {
    
    // Use LibTomMath.
    ltc_mp = ltm_desc;

    // Pass some constants over.
    #define ADD_CONSTANT(name) \
    PyModule_AddObject(m, #name, PyInt_FromLong(name));
    ADD_CONSTANT(CRYPT_OK)
    ADD_CONSTANT(CRYPT_INVALID_PACKET)
    ADD_CONSTANT(CRYPT_PK_INVALID_PADDING)
    ADD_CONSTANT(MAXBLOCKSIZE)
    
}


// We have two different module init functions since I compile to different
// locations for Python 2 vs 3 to ease for rapid testing. They should always
// do the same things.

PyMODINIT_FUNC
init_libtomcrypt2(void)
{
    PyObject *m = Py_InitModule("_libtomcrypt2", tomcrypt_methods);
    init(m);
}


PyMODINIT_FUNC
init_libtomcrypt3(void)
{
    PyObject *m = Py_InitModule("_libtomcrypt3", tomcrypt_methods);
    init(m);
}

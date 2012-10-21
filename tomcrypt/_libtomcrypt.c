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
    ADD_CONSTANT(CRYPT_OK);
    ADD_CONSTANT(CRYPT_INVALID_PACKET);
    ADD_CONSTANT(CRYPT_PK_INVALID_PADDING);
    ADD_CONSTANT(MAXBLOCKSIZE);
    
    PyObject *size_of = PyDict_New();
    PyModule_AddObject(m, "sizeof", size_of);
    #define ADD_SIZEOF(name) \
    PyDict_SetItemString(size_of, #name, PyInt_FromLong(sizeof(name)));
    ADD_SIZEOF(symmetric_ECB);
    ADD_SIZEOF(symmetric_CBC);
    ADD_SIZEOF(symmetric_CTR);
    ADD_SIZEOF(symmetric_CFB);
    ADD_SIZEOF(symmetric_OFB);
    ADD_SIZEOF(symmetric_LRW);
    ADD_SIZEOF(symmetric_F8);
    ADD_SIZEOF(eax_state);
    
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

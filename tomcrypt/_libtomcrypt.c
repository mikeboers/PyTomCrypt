#include <Python.h>
#include "tomcrypt.h"


// We have no methods.
static PyMethodDef tomcrypt_methods[] = {
    {NULL, NULL, 0, NULL}        /* Sentinel */
};


static void init(void) {
    
    // Use LibTomMath.
    ltc_mp = ltm_desc;

}


// We have two different module init functions since I compile to different
// locations for Python 2 vs 3 to ease for rapid testing. They should always
// do the same things.

PyMODINIT_FUNC
init_libtomcrypt2(void)
{
    Py_InitModule("_libtomcrypt2", tomcrypt_methods);
    init();
}


PyMODINIT_FUNC
init_libtomcrypt3(void)
{
    Py_InitModule("_libtomcrypt3", tomcrypt_methods);
    init();
}

#include <Python.h>
#include "tomcrypt.h"


#if PY_MAJOR_VERSION >= 3

    #define PyInt_FromLong PyLong_FromLong

#endif


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
    
    ADD_CONSTANT(CTR_COUNTER_BIG_ENDIAN);
    
    // Pass some sizes over.
    PyObject *sizeof_ = PyDict_New();
    PyModule_AddObject(m, "sizeof", sizeof_);
    #define ADD_SIZEOF(name) \
    PyDict_SetItemString(sizeof_, #name, PyInt_FromLong(sizeof(name)));
    
    ADD_SIZEOF(symmetric_ECB);
    ADD_SIZEOF(symmetric_CBC);
    ADD_SIZEOF(symmetric_CTR);
    ADD_SIZEOF(symmetric_CFB);
    ADD_SIZEOF(symmetric_OFB);
    ADD_SIZEOF(symmetric_LRW);
    ADD_SIZEOF(symmetric_F8);
    ADD_SIZEOF(eax_state);
    
    ADD_SIZEOF(hash_state);
    
    ADD_SIZEOF(hmac_state);
    ADD_SIZEOF(omac_state);
    ADD_SIZEOF(pmac_state);
    ADD_SIZEOF(xcbc_state);
    
}


// We have two different module init functions since I compile to different
// locations for Python 2 vs 3 to ease for rapid testing. They should always
// do the same things.

#if PY_MAJOR_VERSION < 3

    PyMODINIT_FUNC
    init_libtomcrypt2(void)
    {
        PyObject *m = Py_InitModule("_libtomcrypt2", tomcrypt_methods);
        init(m);
    }

# else

    static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        "_libtomcrypt3",     /* m_name */
        "",                  /* m_doc */
        -1,                  /* m_size */
        tomcrypt_methods,    /* m_methods */
        NULL,                /* m_reload */
        NULL,                /* m_traverse */
        NULL,                /* m_clear */
        NULL,                /* m_free */
    };
    
    PyMODINIT_FUNC
    PyInit__libtomcrypt3(void)
    {
        PyObject *m = PyModule_Create(&moduledef);
        init(m);
        return m;
    }

#endif


// Helper functions for Python code.
void copy_hmac_state(hmac_state *from, hmac_state *to, int block_size) {
    to->key = malloc(block_size);
    memcpy(to->key, from->key, block_size);
}

void free_hmac_state(hmac_state *state) {
    if (state->key) {
        free(state->key);
        state->key = NULL;
    }
}


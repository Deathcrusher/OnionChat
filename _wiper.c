#include <Python.h>
#include <string.h>

static PyObject* wipe(PyObject* self, PyObject* obj) {
    Py_buffer view;
    if (PyObject_GetBuffer(obj, &view, PyBUF_WRITABLE) != 0) {
        return NULL;  // propagate exception if object does not support buffer protocol
    }
    volatile unsigned char *p = (volatile unsigned char *)view.buf;
    Py_ssize_t len = view.len;
    for (Py_ssize_t i = 0; i < len; i++) {
        p[i] = 0;
    }
    PyBuffer_Release(&view);
    Py_RETURN_NONE;
}

static PyMethodDef Methods[] = {
    {"wipe", (PyCFunction)wipe, METH_O, "Overwrite a writable buffer with zeros"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "_wiper",
    "Memory wiping utilities",
    -1,
    Methods
};

PyMODINIT_FUNC PyInit__wiper(void) {
    return PyModule_Create(&moduledef);
}

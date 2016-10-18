/*
	malloc_wrapper.c
*/

#include "Python.h"

#ifdef __cplusplus
extern "C" {
#endif

/*malloc()*/
void *__real_malloc(size_t);

void *__wrap_malloc(size_t sz) {
#ifdef Py_PYTHON_H
	return PyMem_RawMalloc(sz);
#else
	return __real_malloc(sz);
#endif
}

void *__real_realloc(void*, size_t);

void *__wrap_realloc(void *ptr, size_t sz) {
#ifdef Py_PYTHON_H
	return PyMem_RawRealloc(ptr, sz);
#else
	return __real_realloc(ptr, sz);
#endif
}

/*free()*/
void __real_free(void*);

void __wrap_free(void *ptr) {
#ifdef Py_PYTHON_H
	PyMem_RawFree(ptr);
#else
	__real_free(ptr);
#endif
}

#ifdef __cplusplus
}
#endif

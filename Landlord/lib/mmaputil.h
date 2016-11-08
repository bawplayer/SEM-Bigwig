/*
	mmaputil.h
*/
#ifndef _MMAPUTIL_H
#define _MMAPUTIL_H

#include "elfutil.h"

typedef struct mmap_tuple_st *MMAP_tuple;
struct mmap_tuple_st {
	int fd; // file descriptor
	pointer_t address; // allocated base address
	int perm; // access permissions
};

#define MMAP_TUPLE_INIT_VAL {.fd=-1, .address=0, .perm=0}

/**
	mmap_alloc_from_fd() allocates a virtual memory segment
	for an opened file. The position pointer is reset.
	@fd - File descriptor (fd >= 0)
	@sz - Returned file size. [Ignored when set to NULL]
	@err - Returned error. [Ignored when set to NULL]
	@RETURN - The allocated vm segment pointer. NULL on error.
*/
pointer_t mmap_alloc_from_fd_writeable(const int fd, size_t *sz, void **err);
pointer_t mmap_alloc_from_fd_readable(const int fd, size_t *sz, void **err);

/**
	mmap_dealloc_from_address() - deallocted a mmap allocation.
	@addr - Valid segment start pointer
	@sz - Segment size (greater than zero)
	@RETURN - (-1) on error, otherwise, 0
*/
int mmap_dealloc_from_address(pointer_t addr, size_t sz);
int mmap_dealloc_with_mmap(MMAP_tuple);

#endif

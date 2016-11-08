/*
	mmaputil.c
*/

#include <unistd.h>
#include <sys/mman.h>
#include "mmaputil.h"
	

static pointer_t mmap_alloc_from_fd_aux(const int fd, size_t *sz, void **err, int prot, int flags);
static inline off_t mmapGetFDOffset(const int fd);
static inline off_t mmapSetFDOffset(const int fd, const off_t offset);


static inline off_t mmapGetFDOffset(const int fd) {
	return lseek(fd, 0, SEEK_CUR);
}

static inline off_t mmapSetFDOffset(const int fd, const off_t offset) {
	return lseek(fd, offset, SEEK_SET);
}

static pointer_t mmap_alloc_from_fd_aux(const int fd, size_t *sz, void **err, int prot, int flags) {
	if (fd < 0) {
		return NULL;
	}

	mmapSetFDOffset(fd, 0);
	size_t file_size = elfFileLength(fd);
	if (prot == 0) {
		prot = PROT_READ | PROT_WRITE;
	}
	if (flags == 0) {
		flags = MAP_SHARED;
	}

	pointer_t addr = mmap(
		NULL, file_size, 
		prot,
		flags,
		fd, 0);
	if ((long)addr <= 0) {	// Validate the returned value
		if (err) {		// Validate error pointer
			*err = addr;// assign the error code
		}				// otherwise, ignore
		return NULL;
	}
	if (sz) {
		*sz = file_size;
	}

	return addr;
}

pointer_t mmap_alloc_from_fd_writeable(const int fd, size_t *sz, void **err) {
	return mmap_alloc_from_fd_aux(fd, sz, err, 0, 0);
}

pointer_t mmap_alloc_from_fd_readable(const int fd, size_t *sz, void **err) {
	return mmap_alloc_from_fd_aux(fd, sz, err, PROT_READ, MAP_PRIVATE);
}

int mmap_dealloc_with_mmap(MMAP_tuple mm) {
	return mmap_dealloc_from_address(mm->address, elfFileLength(mm->fd));
}

int mmap_dealloc_from_address(pointer_t addr, size_t sz) {
	if (!addr || (sz <= 0)) {
		return -1;
	}

	return munmap(addr, sz);
}
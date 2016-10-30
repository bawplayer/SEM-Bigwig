/**
	semutil.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdint.h>
#include "semutil.h"

/*
=============================================================================
                        		MACROS
=============================================================================
*/

#define BITS_IN_BYTE (8)

#define semUpdateSegmentHeadersProtocol(HEADER_TYP, SEG_TYP) do {\
	HEADER_TYP *dest = destaddr; \
	semIncrementNumber(&(dest->e_phnum), sizeof(dest->e_phnum), \
		1, endinessConflictFlag); \
	SEG_TYP *segarray = ((uintptr_t)destaddr + srcHeader64Format.e_ehsize); \
	for (int i = 0; i < srcHeader64Format.e_phnum; ++i)	{ \
		if ((segarray[i].p_offset == 0) && (segarray[i].p_type == PT_LOAD)){ \
			semIncrementNumber(&(segarray[i].p_filesz), \
				sizeof(segarray[i].p_filesz), \
				seg_bytes_copied, endinessConflictFlag); \
			semIncrementNumber(&(segarray[i].p_memsz), \
				sizeof(segarray[i].p_memsz), \
				seg_bytes_copied, endinessConflictFlag); \
			continue; \
		} \
		if (segarray[i].p_offset != 0) { \
			semIncrementNumber(&(segarray[i].p_offset), \
				sizeof(segarray[i].p_offset), \
				seg_bytes_copied, endinessConflictFlag); \
		} \
		if (segarray[i].p_vaddr != 0) { \
			semIncrementNumber(&(segarray[i].p_vaddr), \
				sizeof(segarray[i].p_vaddr), \
				seg_bytes_copied, endinessConflictFlag); \
		} \
		if (segarray[i].p_paddr != 0) { \
			semIncrementNumber(&(segarray[i].p_paddr), \
				sizeof(segarray[i].p_paddr), \
				seg_bytes_copied, endinessConflictFlag); \
		} \
	} \
	semIncrementNumber(&(dest->e_entry), sizeof(dest->e_entry), \
		seg_bytes_copied, endinessConflictFlag); \
} while(0)

#define semSegmentHeaderInitVal {\
		.p_type=1, /* type: load */ \
		.p_offset=0, /*srcfilelength, - offset */ \
		.p_vaddr=segaddr, /* virtual address*/ \
		.p_paddr=segaddr, /* physical address - ignored */ \
		.p_filesz=datalen, /* file footprint*/ \
		.p_memsz=((seglen>datalen)? seglen:datalen), /* memory footprint */ \
		.p_flags=PF_W | PF_R, /* access permissions */ \
		.p_align=1 /* page alignment */ \
}

/*
=============================================================================
                        		DECLARATIONS
=============================================================================
*/

/*
	semCloneFileSectionTableTrimmedAux()
	clonemm is an optional parameter.
*/
static int semCloneFileSectionTableTrimmedAux(const MMAP_tuple srcmm, const char* clonename, MMAP_tuple clonemm, bool);
static int semGetParityAux(const uint8_t *input, int);
static int semAppendLoadSegment(MMAP_tuple srcmm, const char* destname, uintptr_t segaddr, uint8_t *data, unsigned int datalen, unsigned int seglen);
static inline void semSetFDToEnd(const int fd);
static void semReverseBytesOrder(pointer_t x, size_t sz);
static void semIncrementNumber(pointer_t, size_t sz, int, bool reversed);
static int semUpdateSegmentHeaders(int destfd, pointer_t, long);
static inline void semSetFDToEnd(const int fd) {
	lseek(fd, 0, SEEK_END);
}

/*
=============================================================================
                        		IMPLEMENTATIONS
=============================================================================
*/

static int semGetParityAux(const uint8_t *input, int len) {
	if (!input || (len <= 0)) {
		return -1;
	}

	short acc = 0;
	for (int i = 0; i < len; ++i) {
		uint8_t curr = input[i];
		for (int j = 0; j < BITS_IN_BYTE; ++j) {
			if ((curr % 2) != 0) {
				acc ^= 1;
			}
			curr >>= 1; // shift right
		}
	}

	return acc;
}

static void semReverseBytesOrder(pointer_t x, size_t sz) {
	if (x == NULL) {
		return;
	}

	for (int i = 0; i < (sz>>1); ++i) {
		/*swap*/
		uint8_t tmp = *(((uint8_t*)x)+i);
		*(((uint8_t*)x)+i) = *(((uint8_t*)x)+(sz-(i+1)));
		*(((uint8_t*)x)+(sz-(i+1))) = tmp;
	}
}

static void semIncrementNumber(pointer_t x_ptr, size_t sz, int y, bool reversed) {
	if (x_ptr == NULL) {
		return;
	} else if (y == 0) {
		return;
	}

	char reversedBuffer[sz];
	memcpy(reversedBuffer, x_ptr, sz);
	if (reversed) {
		semReverseBytesOrder(reversedBuffer, sz);
	}

	if (sz == sizeof(short)) {
		(*(short*)reversedBuffer) += y;
	} else if (sz == sizeof(int)) {
		(*(int*)reversedBuffer) += y;
	} else if (sz == sizeof(long)) {
		(*(long*)reversedBuffer) += y;
	} else if (sz == sizeof (long long)) {
		(*(long long*)reversedBuffer) += y;
	} else {
		return;
	}

	if (reversed) {
		semReverseBytesOrder(reversedBuffer, sz);
	}
	memcpy(x_ptr, reversedBuffer, sz);
}

int semGetParity(const uint8_t *input, int inputlen, uint8_t *resultarray, int reslen) {
	if (!input || (inputlen < 0) || !resultarray || (reslen <= 0)) {
		return -1;
	} else if (inputlen == 0) {
		return -1;
	} else if ((inputlen < reslen) || (inputlen % (reslen*BITS_IN_BYTE))) {
		return (-2);
	}

	const int divlens = inputlen / (reslen*BITS_IN_BYTE);
	if (divlens < 1) {
		return (-3);
	}

	bzero(resultarray, reslen*sizeof(*resultarray));
	const uint8_t *input_ptr = input;
	for (int i = 0; i < reslen; ++i) {
		for (int j = 0; j < BITS_IN_BYTE; ++j) {
			resultarray[i] |= (semGetParityAux(input_ptr, divlens) << j);
			input_ptr += divlens; // advance pointer
		}
	}

	return 0;
}

static int semCloneFileSectionTableTrimmedAux(const MMAP_tuple srcmm,
	const char* clonename, MMAP_tuple clonemm, bool ignoreLackOfSections) {
	if (!srcmm || !clonename) {
		return -1;
	}
	int err = 0;
	pointer_t srcaddr = srcmm->address;
	int srcfd = srcmm->fd;
	if (!srcaddr) {
		return -1;
	}

	/*Check whether is file statically linked, if not - abort*/
	if (!elfIsStaticLinkedExecutableFile(srcaddr)) {
		return (-4);
	}

	/* Get program size - without section table*/
	Elf64_Ehdr srcHeader64Format;
	if (elfReadHeaderFromAddress(srcaddr, &srcHeader64Format)) {
		return (-6);
	}

	int effectiveSize = elfGetFirstSection64HeaderOffset(&srcHeader64Format);
	if ((effectiveSize == 0) && ignoreLackOfSections) {
		/* No sections table */
		effectiveSize = elfFileLength(srcfd);
	}
	if (effectiveSize <= 0) {
		return (-5);
	}

	FILE *clonefile = fopen(clonename, "w+");
	int clonefd = 0;
	if (!clonefile || ((clonefd = fileno(clonefile)) < 0)) {
		return (-2);
	}

	ssize_t bytes_copied = write(clonefd, srcaddr, effectiveSize);
	if (bytes_copied <= 0) {
		err = (-3);
		goto semtsfefaerr;
	}

	size_t calc_size;
	pointer_t cloneaddr = mmap_alloc_from_fd_writeable(clonefd, &calc_size, NULL);
	if (!cloneaddr || (calc_size != bytes_copied)) {
		//printf("mmap size: %u\tcopied bytes: %u\n", calc_size, bytes_copied);
		err = (-3);
		goto semtsfefaerr;
	}
	elfMarkNoSectionHeaders(cloneaddr);

	if (clonemm) {
		*clonemm = (struct mmap_tuple_st){clonefd, cloneaddr, PROT_READ | PROT_WRITE};
	} else {
		mmap_dealloc_from_address(cloneaddr, bytes_copied);
	}

	/* set execution permission to the cloned file */
	err = (srcfd < 0) ? \
		elfSetExecutableFilePermissionMode(clonefd): \	
		elfCopyFilePermissions(clonefd, srcfd);
	if (err != 0) {
		goto semtsfefaerr;
	}
	
	if (!clonemm) {
		close(clonefd);
	}

	return effectiveSize-bytes_copied;
semtsfefaerr:
	close(clonefd);
	return err;
}

int semCloneFileSectionTableTrimmed(const pointer_t addr, const int srcfd, const char *clonename) {
	if (!addr || (srcfd < 0) || !clonename) {
		return -1;
	}

	struct mmap_tuple_st mm = MMAP_TUPLE_INIT_VAL;
	mm.address = addr;
	mm.fd = srcfd;

	return semCloneFileSectionTableTrimmedAux(&mm, clonename, NULL, false);
}

int semGetEncryptionMagicNumber(const pointer_t addr) {
	if (!addr) {
		return -1;
	}

	return (*(volatile char*)((uintptr_t)addr + SEM_ENC_BIT_HEADER_OFFSET)==0)? 0:1;
}

int semSetEncryptionMagicNumber(pointer_t addr) {
	if (!addr) {
		return -1;
	}

	// really??
	volatile char * const enc_location = (char*)((uintptr_t)addr + SEM_ENC_BIT_HEADER_OFFSET);
	char b = *enc_location;
	*enc_location = 1;
	return b;
}

int semAppendLandlordsSegment(MMAP_tuple srcmm, const char* destname, uintptr_t segaddr,
	const uint8_t *data, unsigned int datalen, unsigned int seglen) {
	struct mmap_tuple_st tmpmm = MMAP_TUPLE_INIT_VAL;
	const char *tmpfilename = "tmp.tmp";
	int res = semCloneFileSectionTableTrimmedAux(srcmm, tmpfilename, &tmpmm, true);
	if (res != 0) {
		return res;
	}

	res = semAppendLoadSegment(&tmpmm, destname, segaddr, data, datalen, seglen);
	mmap_dealloc_with_mmap(&tmpmm);
	close(tmpmm.fd);
	remove(tmpfilename); // delete temporary
	return res;
}

static int semAppendLoadSegment(MMAP_tuple srcmm, const char* destname, uintptr_t segaddr,
	uint8_t *data, unsigned int datalen, unsigned int seglen) {
	if (!srcmm) {
		return -1;
	}

	int srcfd = srcmm->fd;
	pointer_t srcaddr = srcmm->address;
	if (!srcaddr || (srcfd < 0) || !destname || \
		((data == NULL) && (datalen != 0)) || \
		((seglen != 0) && (seglen < datalen))) {
		return -1;
	}

	const bool endinessConflictFlag = elfEndinessConflict(srcaddr);

	Elf64_Ehdr srcHeader64Format;
	if (elfReadHeaderFromAddress(srcaddr, &srcHeader64Format)) {
		return -2;
	}

/*	if (elfIsHeaderType64Class(&srcHeader64Format) ^ (sizeof(Elf_header) == sizeof(Elf64_Ehdr))) {
		if (sizeof(Elf64_Phdr) != sizeof(Elf32_Phdr)) {
			//Header type conflict
			return (-11);
		}
	}
*/

	FILE *destfile = fopen(destname, "w+");
	if (!destfile) {
		return -2;
	}

	int destfd = fileno(destfile);
	if (destfd < 0) {
		fclose(destfile);
		return -2;
	}
	
	/* copy elf header and segment headers */
	size_t srcHeaderTotalSize = elfHeadersTotalSize(srcfd);
	ssize_t bytes_copied = write(destfd, srcaddr, srcHeaderTotalSize);
	if (bytes_copied <= 0) {
		close(destfd);
		return -3;
	}

	/* Append segment header */
	size_t srcfilelength = elfFileLength(srcfd);
	Elf64_Phdr extraelfseghdr64 = semSegmentHeaderInitVal;
	Elf32_Phdr extraelfseghdr32 = semSegmentHeaderInitVal;	

	if ((srcHeader64Format.e_phentsize != sizeof(Elf32_Phdr))
		&& (srcHeader64Format.e_phentsize != sizeof(Elf64_Phdr))) {
		return (-8);
	}
	ssize_t seg_bytes_copied = write(destfd,
		((srcHeader64Format.e_phentsize == sizeof(Elf32_Phdr))? &extraelfseghdr32:&extraelfseghdr64),
		srcHeader64Format.e_phentsize);
	if ((seg_bytes_copied <= 0) || (seg_bytes_copied < srcHeader64Format.e_phentsize)) {
		close(destfd);
		return -4;
	}

	/* Update relevant fields */
	if (semUpdateSegmentHeaders(destfd, srcaddr, seg_bytes_copied)) {
		close(destfd);
		return -5;
	}

	/* Add data to destination */
	semSetFDToEnd(destfd);
	if (write(destfd, (pointer_t)((uintptr_t)srcaddr + srcHeaderTotalSize),
		srcfilelength - srcHeaderTotalSize) <= 0) {
		close(destfd);
		return -6;
	}
	if ((datalen > 0) && (write(destfd, data, datalen) <= 0)) {
		close(destfd);
		return -7;
	}
	
	/* copy permissions */
	elfCopyFilePermissions(destfd, srcfd);
	
	close(destfd);
	//return (datalen>0)? segoffset : 0;
	return 0;
}

static int semUpdateSegmentHeaders(int destfd, pointer_t srcaddr, long seg_bytes_copied) {
	pointer_t destaddr = mmap_alloc_from_fd_writeable(destfd, NULL, NULL);

	Elf64_Ehdr srcHeader64Format;
	if (elfReadHeaderFromAddress(srcaddr, &srcHeader64Format)) {
		return -1;
	}

	const bool endinessConflictFlag = elfEndinessConflict(srcaddr);

	if (elfIsHeaderType64Class(srcaddr)) {
		semUpdateSegmentHeadersProtocol(Elf64_Ehdr, Elf64_Phdr);
	} else {
		semUpdateSegmentHeadersProtocol(Elf32_Ehdr, Elf32_Phdr);
	}

	struct mmap_tuple_st tmpmm = {.fd = destfd, .address=destaddr, .perm=0};
	mmap_dealloc_with_mmap(&tmpmm);

	return 0;
}

uint8_t semEncryptSingleByte(uint8_t srcbyte, uintptr_t va, uint8_t seed, uint8_t key) {
	long otp = va + seed + key;
	return srcbyte ^ (uint8_t)(otp % 256);
}

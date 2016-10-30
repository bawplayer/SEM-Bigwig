/*
	elfutil.c
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "elfutil.h"
#include "semutil.h"


/*
=============================================================================
                        		MACROS
=============================================================================
*/
#define ELF_READ_GEN_HEADER_MEMBER(desthdr, mem, srcptr, endianMismatch, src64bitType, type32hdr, type64hdr) do { \
	size_t srcMemberSize = (src64bitType? MEMBER_SIZE(type64hdr, mem) : MEMBER_SIZE(type32hdr, mem)); \
	size_t destMemberSize = MEMBER_SIZE(type64hdr, mem); \
	char reversedFormBuffer[srcMemberSize]; \
	char *bufptr = srcptr; \
	if (endianMismatch && (srcMemberSize > 1)) { \
		memcpy(reversedFormBuffer, srcptr, srcMemberSize); \
		reverseBytesOrder(reversedFormBuffer, srcMemberSize); \
		bufptr = reversedFormBuffer; \
	} \
	if ((srcMemberSize < destMemberSize) && !elfAmILittleEndian()) { \
		memcpy( \
			(char*)&(((type64hdr*)desthdr)->mem) + (destMemberSize - srcMemberSize), \
			bufptr, srcMemberSize \
		); \
	} else { \
		memcpy((void*)&(((type64hdr*)desthdr)->mem), bufptr, srcMemberSize); \
	} \
	srcptr += srcMemberSize; \
} while (0)

#define ELF_READ_HEAD_MEMBER(desthdr, mem, srcptr, endianMismatch, src64bitType) \
	ELF_READ_GEN_HEADER_MEMBER(desthdr, mem, srcptr, endianMismatch, src64bitType, Elf32_Ehdr, Elf64_Ehdr)

#define ELF_READ_SEGHEAD_MEMBER(desthdr, mem, srcptr, endianMismatch, src64bitType) \
	ELF_READ_GEN_HEADER_MEMBER(desthdr, mem, srcptr, endianMismatch, src64bitType, Elf32_Phdr, Elf64_Phdr)

/*
=============================================================================
                        		DECLARATIONS
=============================================================================
*/

/*
	Use for endiness mismatch.
*/
static void reverseBytesOrder(void*, size_t);

static inline off_t elfGetFDOffset(const int fd);
static inline off_t elfSetFDOffset(const int fd, const off_t offset);
static inline FILE *convertFDtoFILE(const int fd, const char* permit);
static unsigned long elfGetSegmentHeaderOffsetIndex(const Elf_header *hdr, int idx);
static inline unsigned int elfGetSegmentHeaderTableEntriesCount(const Elf_header *hdr);
static int elfCopySegmentsHeaders(const pointer_t, Elf64_Phdr**);
static uint8_t **elfReadSegmentsContentAux(const pointer_t, int);
static bool checkOverlappingAddresses(pointer_t dest, pointer_t src, size_t offset);
static bool isStaticLinkedExecutableFile(const pointer_t addr);
static int elfGetFileType(const pointer_t addr);
static long elfTranslateOffsetsArrayToDomainsAux(pointer_t addr, Elf_offset *offsort, int len, Domain *domains);
static int elfParseSegmentHeaderTo64Version(Elf64_Phdr * const dest, const pointer_t src, bool, bool);
extern bool elfCheckValidity(const uint8_t*);
extern bool elfEndinessConflict(const Elf64_Ehdr*);


/*
=============================================================================
                        		IMPLEMENTATIONS
=============================================================================
*/

static inline off_t elfGetFDOffset(const int fd) {
	return lseek(fd, 0, SEEK_CUR);
}

static inline off_t elfSetFDOffset(const int fd, const off_t offset) {
	return lseek(fd, offset, SEEK_SET);
}

static int elfGetFileType(const pointer_t addr) {
	if (!addr) {
		return -1;
	}

	unsigned short res = ((Elf_header*)addr)->e_type;
	if (elfEndinessConflict((Elf64_Ehdr*)addr)) {
		reverseBytesOrder(&res, sizeof(res));
	}

	return res; // cast from unsigned short to integer
}

static inline FILE *convertFDtoFILE(const int fd, const char* permit) {
	if (fd < 0) {
		return NULL;
	}

	return fdopen(fd, (permit? permit : "r"));
}

int elfIsHeaderType64Class(const Elf64_Ehdr *hdr) {
	if (!hdr) {
		return (-1);
	}

	switch(hdr->e_ident[EI_CLASS]) {
		case 2:
			return 1;
		case 1:
			return 0;
		default: /* error */
			return (-1);
	}
}

static unsigned long elfGetSegmentHeaderOffsetIndex(const Elf_header *hdr, int idx) {
	if (!hdr) {
		return 0;
	}

	bool flag64bheader = elfIsHeaderType64Class(hdr);
	bool endianMismatch = elfEndinessConflict(hdr);
	short phnum = flag64bheader? ((Elf64_Ehdr*)hdr)->e_phnum:((Elf32_Ehdr*)hdr)->e_phnum;
	if (endianMismatch) {
		reverseBytesOrder(&phnum, sizeof(phnum));
	}
	if ((idx < 0) || (idx >= phnum)) { // validate idx
		return 0;
	}

	unsigned long phoff;
	if (endianMismatch) {
		if (flag64bheader) {
			unsigned long _phofftmp = ((Elf64_Ehdr*)hdr)->e_phoff;
			reverseBytesOrder(&_phofftmp, sizeof(_phofftmp));
			phoff = _phofftmp;
		} {
			unsigned int _phofftmp = ((Elf64_Ehdr*)hdr)->e_phoff;
			reverseBytesOrder(&_phofftmp, sizeof(_phofftmp));
			phoff = _phofftmp;
		}
	} else {
		phoff = flag64bheader? ((Elf64_Ehdr*)hdr)->e_phoff:((Elf32_Ehdr*)hdr)->e_phoff;
	}
	
	if (phoff == 0) {
		return 0; /* file has no program header table */
	}

	if (flag64bheader) {
		return ((Elf64_Phdr*)phoff) + idx;
	} else {
		return ((Elf32_Phdr*)phoff) + idx;
	}
}

static void reverseBytesOrder(void *x, size_t sz) {
	if (x == NULL) {
		return;
	}

	for (int i = 0; i < (sz>>1); ++i) {
		/*swap*/
		char tmp = *(((char*)x)+i);
		*(((char*)x)+i) = *(((char*)x)+(sz-(i+1)));
		*(((char*)x)+(sz-(i+1))) = tmp;
	}
}

ssize_t elfFileLength(const int fd) {
	if (fd < 0) {
		return -1;
	}

	off_t currOffset = elfGetFDOffset(fd);
	off_t totalLength = lseek(fd, 0, SEEK_END); //+1
	elfSetFDOffset(fd, currOffset); // leave offset unchanged
	return totalLength;
}

static inline unsigned int elfGetSegmentHeaderTableEntriesCount(const Elf_header *hdr) {
	if (hdr == NULL) {
		return 0;
	}

	bool endianMismatch = elfEndinessConflict(hdr);
	unsigned short res;
	if (hdr->e_ident[EI_CLASS] == 1) {
		res = ((Elf32_Ehdr*)hdr)->e_phnum;
	} else if (hdr->e_ident[EI_CLASS] == 2) {
		res = ((Elf64_Ehdr*)hdr)->e_phnum;
	} else {
		return 0;
	}

	if (endianMismatch) {
		reverseBytesOrder(&res, sizeof(res));
	}

	return res;
}

bool elfAmILittleEndian() {
	int num = 1;
	return (*(char*)&num == 1);
}

int elfReadHeaderFromAddress(const pointer_t addr, Elf64_Ehdr *dest) {
	if (!addr || !dest) {
		return -1;
	}

	if (!elfCheckValidity((const uint8_t*)addr)) {
		return -2;
	}

	int endianType = ((Elf_header*)addr)->e_ident[EI_DATA];
	if ((endianType != 1) && (endianType != 2)) {
		return -3;
	}

	int sourceIs64bType = elfIsHeaderType64Class((Elf64_Ehdr*)addr);
	if (sourceIs64bType < 0) {
		return -4;
	}
#ifdef ENVT32
	if (sourceIs64bType) {
		return -5;
	}
#endif

	uint8_t *iter = addr;
	bool endianMismatch = elfAmILittleEndian() ^ (endianType == 1);

	ELF_READ_HEAD_MEMBER(dest, e_ident,		iter, false, sourceIs64bType); // Never reverse bytes order
	ELF_READ_HEAD_MEMBER(dest, e_type,		iter, endianMismatch, sourceIs64bType);
	ELF_READ_HEAD_MEMBER(dest, e_machine,	iter, endianMismatch, sourceIs64bType);
	ELF_READ_HEAD_MEMBER(dest, e_version,	iter, endianMismatch, sourceIs64bType);
	ELF_READ_HEAD_MEMBER(dest, e_entry,		iter, endianMismatch, sourceIs64bType);
	ELF_READ_HEAD_MEMBER(dest, e_phoff,		iter, endianMismatch, sourceIs64bType);
	ELF_READ_HEAD_MEMBER(dest, e_shoff,		iter, endianMismatch, sourceIs64bType);
	ELF_READ_HEAD_MEMBER(dest, e_flags,		iter, endianMismatch, sourceIs64bType);
	ELF_READ_HEAD_MEMBER(dest, e_ehsize,	iter, endianMismatch, sourceIs64bType);
	ELF_READ_HEAD_MEMBER(dest, e_phentsize,	iter, endianMismatch, sourceIs64bType);
	ELF_READ_HEAD_MEMBER(dest, e_phnum,		iter, endianMismatch, sourceIs64bType);
	ELF_READ_HEAD_MEMBER(dest, e_shentsize,	iter, endianMismatch, sourceIs64bType);
	ELF_READ_HEAD_MEMBER(dest, e_shnum,		iter, endianMismatch, sourceIs64bType);
	ELF_READ_HEAD_MEMBER(dest, e_shstrndx,	iter, endianMismatch, sourceIs64bType);

	return 0;	
}

int elfReadHeaderFromFD(const int fd, Elf64_Ehdr* dest) {
	if ((fd < 0) || !dest) {
		return -1;
	}

	int res = 0;
	off_t offset = elfGetFDOffset(fd);
	elfSetFDOffset(fd, 0);

	const size_t elf_hd_size = sizeof(*dest);
	uint8_t buf[elf_hd_size];
	for (int i = 0, bytes_read; i < elf_hd_size; i += bytes_read) {
		/* Read source into buffer*/
		if ((bytes_read = read(fd, buf + i, (elf_hd_size-i))) <= 0) {
			res = (bytes_read < 0)? bytes_read : -1;
			goto ehresetoffset;
		}
	}

	res = elfReadHeaderFromAddress(buf, dest);

ehresetoffset:
	elfSetFDOffset(fd, offset);
	return res;
}

static int elfParseSegmentHeaderTo64Version(Elf64_Phdr * const dest, const pointer_t srcHeader,
	bool endianMismatch, bool sourceIs64bit) {
	if (!srcHeader || !dest) {
		return -1;
	}

	uint8_t *iter = srcHeader;
	ELF_READ_SEGHEAD_MEMBER(dest, p_type, iter, endianMismatch, sourceIs64bit);
	ELF_READ_SEGHEAD_MEMBER(dest, p_flags, iter, endianMismatch, sourceIs64bit);
	ELF_READ_SEGHEAD_MEMBER(dest, p_offset, iter, endianMismatch, sourceIs64bit);
	ELF_READ_SEGHEAD_MEMBER(dest, p_vaddr, iter, endianMismatch, sourceIs64bit);
	ELF_READ_SEGHEAD_MEMBER(dest, p_paddr, iter, endianMismatch, sourceIs64bit);
	ELF_READ_SEGHEAD_MEMBER(dest, p_filesz, iter, endianMismatch, sourceIs64bit);
	ELF_READ_SEGHEAD_MEMBER(dest, p_memsz, iter, endianMismatch, sourceIs64bit);
	ELF_READ_SEGHEAD_MEMBER(dest, p_align, iter, endianMismatch, sourceIs64bit);

	return 0;
}

ssize_t elfHeadersTotalSize(const int fd) {
	Elf64_Ehdr hdr;
	int res = elfReadHeaderFromFD(fd, &hdr);
	if (res != 0) {
		return (res < 0)? res : (-1);
	}

	return hdr.e_ehsize + hdr.e_phnum * hdr.e_phentsize;
}

static int elfCopySegmentsHeaders(const pointer_t addr, Elf64_Phdr **res) {
	if (!addr) {
		return -1;
	}

	int segments_count = elfGetSegmentHeaderTableEntriesCount(addr);
	if (segments_count <= 0) {
		return -1;
	}

	if ((*res = malloc(sizeof(**res)*(segments_count))) == NULL) {
		return -2;
	}

	bool flag64bheader = elfIsHeaderType64Class(addr);
	bool endianMismatch = elfEndinessConflict(addr);

	for (int i = 0; i < segments_count; ++i) {
		pointer_t segHeader = elfGetSegmentHeaderOffsetIndex(addr, i) + (unsigned long)addr;
		if (elfParseSegmentHeaderTo64Version(&((*res)[i]), segHeader, endianMismatch, flag64bheader)) {
			free(*res);
			*res = NULL;
			return -1;
		}
	}

	return segments_count;
}

Elf_segment_header **elfGetSegmentHeadersPointers(const Elf_header *hdr) {
	if (!hdr) {
		return NULL;
	}
	const int segments_count = elfGetSegmentHeaderTableEntriesCount(hdr);
	if (segments_count <= 0) {
		return NULL;
	}

	Elf_segment_header **array = malloc(sizeof(*array) * (segments_count+1));
	if (!array) {
		return NULL;
	}
	array[segments_count] = NULL; // null terminated

	for (int i=0; i < segments_count; ++i) {
		unsigned int headerOffset = elfGetSegmentHeaderOffsetIndex(hdr, i);
		if (headerOffset == 0) {
			free(array);
			return NULL;
		}
		array[i] = (unsigned long)hdr + headerOffset;
	}

	return array;
}

static bool checkOverlappingAddresses(pointer_t dest, pointer_t src, size_t offset) {
	return ((src == dest) && (offset > 0)) || \
		((src < dest) && ((uintptr_t)src+offset > (uintptr_t)dest)) || \
		((src > dest) && ((uintptr_t)dest+offset > (uintptr_t)src));
}

Elf64_Off elfGetFirstSection64HeaderOffset(const Elf64_Ehdr* hdr) {
	return hdr? hdr->e_shoff: 0;
}

void elfMarkNoSectionHeaders(Elf64_Ehdr *hdr) {
	if (!hdr) {
		return;
	}

	int headerIs64Type = elfIsHeaderType64Class(hdr);
	if (headerIs64Type == 1) {
		((Elf64_Ehdr*)hdr)->e_shoff = 0; // offset
		((Elf64_Ehdr*)hdr)->e_shnum = 0; // number
		((Elf64_Ehdr*)hdr)->e_shstrndx = SHN_UNDEF; // string		
	} else if (headerIs64Type == 0) {
		((Elf32_Ehdr*)hdr)->e_shoff = 0; // offset
		((Elf32_Ehdr*)hdr)->e_shnum = 0; // number
		((Elf32_Ehdr*)hdr)->e_shstrndx = SHN_UNDEF; // string
	}
}

int elfCopyFilePermissions(const int destfd, const int srcfd) {
	if ((destfd < 0) || (srcfd < 0) || (destfd == srcfd)) {
		return -1;
	}

	struct stat buf;
	if (fstat(srcfd, &buf) == -1) {
		return -1;
	}

	return fchmod(destfd, buf.st_mode);
}

int elfSetExecutableFilePermissionMode(const int fd) {
	return fchmod(fd, S_IXUSR | S_IXGRP | S_IXOTH); // give execute permissions
}

/**
	Traslate array of offsets to array of domains: (baseaddr, size)
*/
static long elfTranslateOffsetsArrayToDomainsAux(pointer_t addr, Elf_offset *offsort, int len, Domain *domains) {
	if (!addr || !offsort || (len <= 0)) {
		return -1;
	}

	Domain domainsArray = NULL;
	unsigned long currbaseaddr = 0, currlength = 0;
	long elementsCount = 0;
	for (int i = 0; i < len; ++i) {
		unsigned long curraddr = (unsigned long)addr + offsort[i];
		if (curraddr == currbaseaddr + currlength) { // following
			++currlength;
			continue;
		} else if (currlength > 0) {
			if ((domainsArray = realloc(domainsArray, (++elementsCount * sizeof(*domainsArray)))) == NULL) {
				return -1;
			}
			domainsArray[elementsCount-1].baseaddr = currbaseaddr;
			domainsArray[elementsCount-1].length = currlength;
		}
		currbaseaddr = curraddr;
		currlength = 1;
	}
	if (currlength > 0) {
		if ((domainsArray = realloc(domainsArray, (++elementsCount * sizeof(*domainsArray)))) == NULL) {
			return -1;
		}
		domainsArray[elementsCount-1].baseaddr = currbaseaddr;
		domainsArray[elementsCount-1].length = currlength;
	}

	*domains = domainsArray;
	return elementsCount;
}

int elfUnsetBytes(pointer_t addr, Elf_offset *offsort, int len) {
	if (!addr || !offsort || (len <= 0)) {
		return -1;
	}

	Domain domainsArray = NULL;
	long elementsCount = elfTranslateOffsetsArrayToDomainsAux(addr, offsort, len, &domainsArray);
	if (elementsCount <= 0) {
		return -1;
	}

	for (unsigned long i = 0; i < elementsCount; ++i) {
		bzero(domainsArray[i].baseaddr, domainsArray[i].length); // nullify
	}
	
	free(domainsArray);

	return 0;
}

void elfNullifyDomain(Domain d) {
	if (d) {
		bzero((pointer_t)(d->baseaddr), d->length);
	}
}

int elfIsStaticLinkedExecutableFile(const pointer_t addr) {
	if (!addr) {
		return -1;
	} else if (!elfCheckValidity(addr)) {
		return (-1);
	}

	if (elfGetFileType(addr) != 2) {
		/* Not executable file */
		return (-3);
	}

	int res = 1;

	int segments_count = 0;
	Elf_segment_header *segheaders = NULL;
	if (((segments_count = elfCopySegmentsHeaders(addr, &segheaders) )<= 0)
		|| !segheaders) {
		res = -1;
		goto eisttleffex;
	}

	for (int i = 0; i<segments_count; ++i) {
		if (segheaders[i].p_type == PT_INTERP) {
			res = 0;
			break;
		}
	}

eisttleffex:
	free(segheaders);
	return res;
}

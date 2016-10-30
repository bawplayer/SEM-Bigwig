/**
elfutil.h
*/

#ifndef _ELFUTIL_H
#define _ELFUTIL_H

#include <stdbool.h>
#include <sys/types.h>
#define ELF_TARGET_ALL
#include <elf.h>

#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)

/*Define either 32b or 64b environment*/
#if defined (__FORCE_64B__)
	#define ENVT64
#elif defined (__FORCE_32B__)
	#define ENVT32
#elif __GNUC__
	#if __x86_64__ || __ppc64__
		#define ENVT64
	#else
		#define ENVT32
	#endif
#endif

/*Define ELF-related types*/
#ifdef ENVT64
	#define Elf_header Elf64_Ehdr
	#define Elf_segment_header Elf64_Phdr
	#define Elf_section_header Elf64_Shdr
	#define Elf_sym_table Elf64_Sym
	#define Elf_rel Elf64_Rel
	#define Elf_rela Elf64_Rela
	#define Elf_addr Elf64_Addr
	#define Elf_offset Elf64_Off
#else
	#define Elf_header Elf32_Ehdr
	#define Elf_segment_header Elf32_Phdr
	#define Elf_section_header Elf32_Shdr
	#define Elf_sym_table Elf32_Sym
	#define Elf_rel Elf32_Rel
	#define Elf_rela Elf32_Rela
	#define Elf_addr Elf32_Addr
	#define Elf_offset Elf32_Off
#endif

#define Elf_word uint32_t
#define Elf_half uint16_t
#define pointer_t void*

typedef struct domain_st *Domain;
struct domain_st {
	pointer_t baseaddr;
	size_t length;
};

#define ELF_SEG_HEAD_NUM_FIELD 8

/**
	Returns a 64bit version ELF header representation of the file,
	given a valid file descriptor. Endiness of the returned header matches that
	of the running machine, no matter the endiness of the source.
	@RETURN - 0 on success, otherwise negative.
*/
int elfReadHeaderFromFD(const int fd, Elf64_Ehdr*);
int elfReadHeaderFromAddress(const pointer_t addr, Elf64_Ehdr*);

/**
	elfFileLength() returns the length of the an opened file.
	@fd - File descriptor.
	The position pointer (inside the file) is kept.
*/
ssize_t elfFileLength(const int fd);

/**
	elfGetPartialSegmentHeadersFromAddress() retreives 4 parameters of each
	segment header of the given mmap-ed ELF file.
	@addr - The address of the begining of the mapped file.
	@res - A pointer to an unsigned long array, to be allocated by
			the callee.
	@RETURN - (-1) if error, otherwise, the res' length.
*/
int elfGetPartialSegmentHeadersFromAddress(pointer_t addr, unsigned long **res);

/**
	elfGetSegmentHeadersPointers() returns a new null-terminated array of pointers,
	to the mapped file. Representing the segment headers.
	The caller has to free the array.
	@hdr - the mapped file address.
*/
Elf_segment_header **elfGetSegmentHeadersPointers(const Elf_header *hdr);

/**
	elfCheckValidity() verifies magic number.
*/
inline bool elfCheckValidity(const uint8_t *buf) {
	return buf && (buf[0] == 0x7F) && (buf[1] == 'E') && (buf[2] == 'L') && (buf[3] == 'F');
}

/**
	Returns True when the current machine's endiness is little-endian.
*/
bool elfAmILittleEndian();

/**
	Return True when the endiness of the target header doesn't match
	the machine's, provided hdr is not NULL.
	It works for both 32bit and 64bit version headers, no matter the
	machine.
*/
inline bool elfEndinessConflict(const Elf64_Ehdr* hdr) {
	return hdr && (elfAmILittleEndian() ^ (hdr->e_ident[EI_DATA] == 1));
}

/**
	elfHeadersTotalSize() returns the sum of:
	ELF header size + the segments headers total size
	-1 on error.
*/
ssize_t elfHeadersTotalSize(const int fd);

/**
	Works for both 64bit and 32bit ELF headers.
	Returns 0 for 32b, 1 for 64b, -1 for error.
*/
int elfIsHeaderType64Class(const Elf64_Ehdr*);

/**
	elfUnsetBytes() unsets the data in given addresses
	@addr - File mapped base address
	@off - Offsets sorted array
	@len - The array's elfFileLength
*/
int elfUnsetBytes(pointer_t addr, Elf_offset *offsort, int len);
void elfNullifyDomain(Domain);

/**
	elfIsStaticLinkedExecutableFile() rules out that either of the
	program (segment) headers is interpreter type.
	Returns (-1) on memeory allocation error. Otherwise, 0 or 1.
*/
int elfIsStaticLinkedExecutableFile(const pointer_t addr);

Elf64_Off elfGetFirstSection64HeaderOffset(const Elf64_Ehdr* hdr);

int elfCopyFilePermissions(const int destfd, const int srcfd);
int elfSetExecutableFilePermissionMode(const int fd);

/**
	Modify the ELF header to represent the absence of sections table.
	Works for both 64bit and 32bit ELF headers.
*/
void elfMarkNoSectionHeaders(Elf64_Ehdr*);

#endif

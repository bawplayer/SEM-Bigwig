/**
	semutil.h
*/

#ifndef _SEMUTIL_H
#define _SEMUTIL_H

#include "elfutil.h"
#include "mmaputil.h"

#define SEM_ENC_BIT_HEADER_OFFSET 8

/**
	Creates a new file 	named @clonename, without the section table.
	@addr - the mmap address
	@fdsrc - when valid (>=0), the function will copy current
		access file permissions of the original to its clone.
	@clonename - the name of the new file
	@RETURN - 0 for success.
*/
int semCloneFileSectionTableTrimmed(const pointer_t addr, const int, const char *clonename);

int semSetEncryptionMagicNumber(pointer_t addr);
int semGetEncryptionMagicNumber(const pointer_t addr);

/**
	Encrypt the file's content and signatures.
	@PARAM1 - Result of elfGetSegmentsHeadersFromAddress() - Segments' headers
	@PARAM2 - Result of elfReadSegmentsContent() - Segments' content
	@PARAM3 - Result of elfSignSegmentsContent() - Segments' content signatures
	@RETURN - 0 on success
*/
int semEncryptContentAndSignature(const unsigned long*, uint8_t**, uint8_t**);


uint8_t semEncryptSingleByte(uint8_t srcbyte, uintptr_t va, uint8_t seed, uint8_t key);

/**
	semAppendLandlordsSegment() appends a data segment to a file.
	Parameters:
		@srcmm - Source file file descriptor and mapped address
		@destname - destination file name
		@segaddr - Segment's virtual address
		@data - Segment data
		@datalen - Segment data length
		@seglen - Segment memory footprint (meaningful only when >= datalen)
		@RETURN - Segment offset in the file
*/
int semAppendLandlordsSegment(MMAP_tuple, const char*, uintptr_t segaddr,
	const uint8_t *data, unsigned int datalen, unsigned int seglen);

/**
	semGetParity() returns the corresponding parity bits of input array.
	Parameters:
		@input - input data
		@intputlen - input array's length (number of bytes)
		@resultarray - array of which the parity bits will be placed
		@reslen - result array's length (number of bytes)
		@RETURN - 0 for success
*/
int semGetParity(const uint8_t *input, int inputlen, uint8_t *resultarray, int reslen);

#endif

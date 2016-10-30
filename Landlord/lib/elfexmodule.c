/**
	elfexmodule.c
	The Python library includes: stdio, string, errno, stdlib, assert, limits.
*/
#include <Python.h> 
#include <stdbool.h>
#include "elfutil.h"
#include "semutil.h"
#include "mmaputil.h"


/*
=============================================================================
                        		MACROS
=============================================================================
*/
#define PAGE_SIZE 4096

#define releasePyObject(x) do { \
	Py_XDECREF(x); \
	x = NULL; \
} while(0)


#define GetElfileUnsignedLongVariable(srcobj, var) \
	(PyLong_AsUnsignedLongMask(PyObject_GetAttrString(srcobj, var)))
#define GetElfileUnsignedLongSubVariable(srcobj, extvar, intvar) \
	(PyLong_AsUnsignedLongMask(PyObject_GetAttrString(PyObject_GetAttrString(srcobj, extvar), intvar)))

/*
=============================================================================
                        		DECLARATIONS
=============================================================================
*/

typedef int (*hashFunction)(const pointer_t, int, pointer_t, int, int);
typedef uint8_t (*encFunction)(uint8_t, uintptr_t, uint8_t, uint8_t);

static PyObject *ExmodError;
static PyObject *elfexmod_retrieveStringFromMappedFile(PyObject*, PyObject*);
static PyObject *elfexmod_mmapAlloc(PyObject*, PyObject*, PyObject*);
static PyObject *elfexmod_mmapDealloc(PyObject*, PyObject*);
static PyObject *elfexmod_checkValidity(PyObject*, PyObject*);
static PyObject *elfexmod_isEncrypted(PyObject*, PyObject*);
static PyObject *elfexmod_markEncrypted(PyObject*, PyObject*);
static PyObject *elfexmod_fileLength(PyObject*, PyObject*);
static PyObject *elfexmod_readHeader(PyObject*, PyObject*);
static PyObject *elfexmod_readSegmentsTable(PyObject*, PyObject*);
static PyObject *elfexmod_trimSections(PyObject*, PyObject*);
static PyObject *elfexmod_fileHeaderLength(PyObject*, PyObject*);
static PyObject *elfexmod_nullifyDomains(PyObject*, PyObject*);
static PyObject *elfexmod_appendLandlords(PyObject*, PyObject*);
static PyObject *elfexmod_encBytesArray(PyObject*, PyObject*);
static PyObject *elfexmod_signBytesArray(PyObject*, PyObject*);
static PyObject *elfexmod_signFile(PyObject*, PyObject*);
static PyObject *elfexmod_signAux(const char *dataarray, int arraysize, int, int, hashFunction);
static PyObject *elfexmod_isStaticallyLinkedExecutable(PyObject*, PyObject*);
inline static int py_singleSetToDict(PyObject* dest, const char *src, const char *key, const char *format);
static char *swap4bytes(char *dest, const char *src);
static char *swapBytesEndian(char *dest, const char *src, int n);
inline static int getParityWrapper(const uint8_t *input, int, uint8_t*, int, int);


/*
=============================================================================
                        		IMPLEMENTATIONS
=============================================================================
*/

inline static int py_singleSetToDict(PyObject* dest, const char *src, const char *key, const char *format) {
	int res = 0;
	PyObject *_tmp = Py_BuildValue(format, src);
	if (!_tmp || PyDict_SetItemString(dest, key, _tmp)) {
		res = -1;
	}
	Py_XDECREF(_tmp);
	return res;
}

/**
	swapBytesEndian() is used when code targeted for machine
	with the different endiness policy is parsed.
	@RETURN - destination
*/
static char *swapBytesEndian(char *dest, const char *src, int n) {
	if (!dest || !src || (n<0)) {
		return NULL;
	}

	for (int i = 0; i < n; ++i) {
		dest[i] = src[n-(i+1)];
	}

	return dest;
}

static char *swap4bytes(char *dest, const char *src) {
	return swapBytesEndian(dest, src, 4);
}

PyDoc_STRVAR(nullifyDomains_doc,
"nullifyDomains(self)\n\n"
"Given a list of domains, writes zeros into them");
static PyObject *elfexmod_nullifyDomains(PyObject *self, PyObject *args) {
	ssize_t len;
	PyObject *pylist = NULL;
	if (!PyArg_ParseTuple(args, "O", &pylist) || !pylist || \
		!PyList_Check(pylist) || \
		((len = PyList_Size(pylist)) < 0)) {
		PyErr_SetString(PyExc_TypeError, "Expected a list");
		return NULL;
	} else if (len == 0) {
		PyErr_SetString(PyExc_TypeError, "List is empty");
		return NULL;
	}

	/* Unpack the list */
	for (unsigned long i = 0; i < len; ++i) {
		struct domain_st curr;		
		if (!PyArg_Parse(PyList_GetItem(pylist, i), "(ll)", &(curr.baseaddr), &(curr.length))) {
			PyErr_BadArgument();
			return NULL;
		} else if (curr.length <= 0) {
			PyErr_SetString(PyExc_TypeError, "Illegal domain");
			return NULL;
		}
		elfNullifyDomain(&curr);
	}

	Py_RETURN_NONE;
}

PyDoc_STRVAR(fileLength_doc,
"fileLength(self) -> int\n\n"
"Given a valid file descriptor, returns the file's length");
static PyObject *elfexmod_fileLength(PyObject *self, PyObject *args) {
	int fd;
	PyObject *selfobj = NULL;
	if (!PyArg_ParseTuple(args, "O", &selfobj) || !selfobj || \
		((fd = GetElfileUnsignedLongVariable(selfobj, "fileno")) < 0)) {
		PyErr_BadArgument();
		return NULL;
	}

	long res = elfFileLength(fd);
	if (res < 0) {
		return PyErr_SetFromErrno(PyExc_IOError);
	}
	return PyLong_FromUnsignedLong(res);
}

PyDoc_STRVAR(fileHeaderLength_doc,
"fileHeaderLength(self) -> int\n\n"
"Given a valid file descriptor, returns the ELF header length + the segment headers size");

static PyObject *elfexmod_fileHeaderLength(PyObject *self, PyObject *args) {
	int fd;
	PyObject *selfobj = NULL;
	if (!PyArg_ParseTuple(args, "O", &selfobj) || !selfobj || \
		((fd = GetElfileUnsignedLongVariable(selfobj, "fileno")) < 0)) {
		PyErr_BadArgument();
		return NULL;
	}

	long res = elfHeadersTotalSize(fd);
	if (res < 0) {
		return PyErr_SetFromErrno(PyExc_IOError);
	}
	return PyLong_FromUnsignedLong(res);
}

PyDoc_STRVAR(isStaticallyLinkedExecutable_doc,
"isStaticallyLinkedExecutable(self) -> bool\n\n"
"Excutable File && StaticallyLinked");
static PyObject *elfexmod_isStaticallyLinkedExecutable(PyObject *self, PyObject *args) {
	uintptr_t addr = 0;
	PyObject *selfobj = NULL;
	if (!PyArg_ParseTuple(args, "O", &selfobj) || !selfobj || \
		((addr = GetElfileUnsignedLongSubVariable(selfobj, "_srcmm", "address")) == 0)) {
		PyErr_BadArgument();
		return NULL;
	}

	long res = elfIsStaticLinkedExecutableFile((pointer_t)addr);
	if (res < 0) {
		if (res == (-3)) {
			PyErr_Format(PyExc_ValueError, "Not executable file");
			return NULL;
		}
		return PyErr_SetFromErrno(PyExc_MemoryError);
	}
	return PyBool_FromLong(res);
}

PyDoc_STRVAR(isEncrypted_doc,
"isEncrypted(self) -> bool\n\n"
"Checks magic number");
static PyObject *elfexmod_isEncrypted(PyObject *self, PyObject *args) {
	uintptr_t addr = 0;
	PyObject *selfobj = NULL;
	if (!PyArg_ParseTuple(args, "O", &selfobj) || !selfobj || \
		((addr = GetElfileUnsignedLongSubVariable(selfobj, "_srcmm", "address")) == 0)) {
		PyErr_BadArgument();
		return NULL;
	}

	long res = semGetEncryptionMagicNumber((pointer_t)addr);
	if (res < 0) {
		return PyErr_SetFromErrno(PyExc_IOError);
	}
	return PyBool_FromLong(res);
}

PyDoc_STRVAR(trimSections_doc,
"trimSections(self, cloneName:str)\n\n"
"Create a new file that correspondes with @cloneName. "
"The clone file will be stripped of the source's section headers.\n"
"Note: section headers are reduntant in statically-linked executables.");
static PyObject *elfexmod_trimSections(PyObject *self, PyObject *args) {
	uintptr_t addr = 0;
	long fd;
	char *clonename;
	PyObject *selfobj = NULL;

	if (!PyArg_ParseTuple(args, "Os", &selfobj, &clonename) || \
		!selfobj || \
		((addr = GetElfileUnsignedLongSubVariable(selfobj, "_srcmm", "address")) == 0) || \
		((fd = GetElfileUnsignedLongVariable(selfobj, "fileno")) < 0) || \
		!clonename) {
		PyErr_BadArgument();
		return NULL;
	}
	
	int res = semCloneFileSectionTableTrimmed((pointer_t)addr, fd, clonename);
	if (res != 0) {
		if (res == -4) { /* Invalid file */
			PyErr_Format(PyExc_ValueError, "Source file must be executable and statically-linked");
			return NULL;
		} else if (res == -5) {
			PyErr_Format(PyExc_ValueError, "File has no section-table");
			return NULL;
		} else {
			return PyErr_SetFromErrno(PyExc_IOError);
		}
	}
	
	Py_RETURN_NONE;
}

PyDoc_STRVAR(appendLandlords_doc,
"appendLandlords(self, destname:str, segaddr:uintptr_t, seglen:int=0, byteobj:bytearray=None) -> int\n\n"
"Append landlord segment to executable. "
"Returns the offset of the new segment in the file.");
static PyObject *elfexmod_appendLandlords(PyObject *self, PyObject *args) {
	uintptr_t segaddr = 0;
	char *destname = NULL;
	PyObject *selfobj = NULL, *byteobj = NULL;
	unsigned int datalen = 0, seglen = 0;
	struct mmap_tuple_st srcmm = MMAP_TUPLE_INIT_VAL;

	if (!PyArg_ParseTuple(args, "OsI|IO", &selfobj, &destname, &segaddr, &seglen, &byteobj) || \
		!selfobj || \
		((srcmm.address = GetElfileUnsignedLongSubVariable(selfobj, "_srcmm", "address")) == 0) || \
		((srcmm.fd = GetElfileUnsignedLongVariable(selfobj, "fileno")) < 0) || \
		!destname || \
		(byteobj && !PyBytes_Check(byteobj))) {
		PyErr_BadArgument();
		return NULL;
	}

	datalen = byteobj? PyBytes_Size(byteobj):0;
	int res = semAppendLandlordsSegment(&srcmm, destname, segaddr, \
		((datalen>0)? PyBytes_AsString(byteobj):NULL), datalen, \
		seglen);
	if (res < 0) {
		if (res == (-10)) {
			PyErr_Format(PyExc_NotImplementedError, "Endiness conflict");
		} else if (res == (-11)) {
			PyErr_Format(PyExc_NotImplementedError, "64bit class conflict");
		} else {
			PyErr_Format(PyExc_IOError, "%d", res);
		}
		return NULL;
	}

	return PyBool_FromLong(res);
}

inline static int getParityWrapper(const uint8_t *input, int inputlen, uint8_t *resultarray, int reslen, int key) {
	// ignore key
	return semGetParity(input, inputlen, resultarray, reslen);
}

PyDoc_STRVAR(signAux_doc,
"signAux(const cchar*, cint arraysize, cint cacheline_width, cint sign_width) -> bytes\n\n"
"Arguments are given in C, but returns a Python bytes object.");
static PyObject *elfexmod_signAux(const char *dataarray, int arraysize, int cacheline_width, int sign_width,
	hashFunction hashfunc) {
	if (!dataarray || (arraysize <= 0) || (cacheline_width <= 0) || (sign_width <= 0)) {
		PyErr_BadArgument();
		return NULL;
	} else if ((arraysize < cacheline_width) || (arraysize % cacheline_width != 0)) {
		PyErr_Format(PyExc_ValueError, "data size (%d) must be divisible by cacheline width (%d)", arraysize, cacheline_width);
		return NULL;
	}

	PyObject *resultobj = NULL;
	const char *dataptr = dataarray;
	uint8_t parityBuffer[sign_width+1];
	int encResult = 0;
	for (unsigned int i = 0; i < arraysize/cacheline_width; ++i, dataptr += cacheline_width) {
		/*Fill parityBuffer with the parity calculation of the current cacheline*/
		if ((encResult = hashfunc(dataptr, cacheline_width, parityBuffer, sign_width, 0)) != 0) {
			goto elfsgnauxerr;
		}

		/*Build Python Bytes object from parityBuffer*/
		PyObject *tmpobj = PyBytes_FromStringAndSize(parityBuffer, sign_width);
		if (!tmpobj) {
			goto elfsgnauxerr;
		}

		if (!resultobj) {
			/*On first iteration - assign tmpobj to resultobj*/
			resultobj = tmpobj;
			Py_XINCREF(resultobj);
		} else {
			/*On itertion>1st - concatenate tmpobj to resultobj*/
			PyBytes_ConcatAndDel(&resultobj, tmpobj);
			if (!resultobj) { /* Null upon failure*/
				return PyErr_SetFromErrno(PyExc_MemoryError);
			}
		}
	}

	return resultobj;
elfsgnauxerr:
	if (resultobj) {
		Py_XDECREF(resultobj);
	}
	if (encResult) {
		PyErr_Format(PyExc_ValueError, "semGetParity(%d, %d) returned err: (%d)",
			cacheline_width, sign_width, encResult);
		return NULL;
	}
	return PyErr_SetFromErrno(PyExc_MemoryError);
}

PyDoc_STRVAR(signBytesArray_doc,
"signBytesArray(obj:bytes, cacheline_width:int, sign_width:int) -> bytes\n\n"
"Return a signature for the given bytes object");
static PyObject *elfexmod_signBytesArray(PyObject *self, PyObject *args) {
	int cacheline_width = 0, sign_width = 0;
	PyObject *bytesobj = NULL;
	if (!PyArg_ParseTuple(args, "Oii", &bytesobj, &cacheline_width, &sign_width) || \
		!bytesobj || (cacheline_width <= 0) || (sign_width <= 0)) {
		PyErr_BadArgument();
		return NULL;
	} else if (!PyBytes_Check(bytesobj)) {
		PyErr_Format(PyExc_TypeError, "content must be of type bytes");
		return NULL;
	}

	if (PyBytes_Size(bytesobj) < cacheline_width) {
		PyErr_Format(PyExc_TypeError,
			"content (%d) must be at minimum size of cacheline_width (%d)",
			PyBytes_Size(bytesobj), cacheline_width);
		return NULL;
	}

	return elfexmod_signAux(PyBytes_AsString(bytesobj), PyBytes_Size(bytesobj),
		cacheline_width, sign_width, &getParityWrapper);
}

PyDoc_STRVAR(encBytesArray_doc,
"encBytesArray(obj:bytes, key:int, start_va:int=0) -> bytes\n\n"
"Return the encrypted string.\nAssuming small-endian, and seed=0 for all.");
static PyObject *elfexmod_encBytesArray(PyObject *self, PyObject *args) {
	int key, start_va = 0;
	PyObject *bytesobj = NULL;
	if (!PyArg_ParseTuple(args, "Oi|i", &bytesobj, &key, &start_va) || \
		!bytesobj || (start_va < 0)) {
		PyErr_BadArgument();
		return NULL;
	} else if (!PyBytes_Check(bytesobj)) {
		PyErr_Format(PyExc_TypeError, "content must be of type bytes");
		return NULL;
	}

	/* parse to C type*/
	const char *srcString = PyBytes_AsString(bytesobj);
	if (srcString == NULL) {
		return PyErr_NoMemory;
	}
	size_t srcLength = PyBytes_Size(bytesobj);
	if (srcLength <= 0) {
		return PyErr_NoMemory;
	}
/*
	char *resultString = malloc(sizeof(srcLength));
	if (resultString == NULL) {
		return PyErr_NoMemory;
	}
*/
	char resultString[srcLength]; /* Malloc didn't work well */
	for (int i = 0; i < srcLength; ++i) {
		resultString[i] = semEncryptSingleByte(srcString[i], start_va + i, 0, key);
	}

	/* Parse to Pythonic type */
	PyObject *resobj = PyBytes_FromStringAndSize(resultString, srcLength);

	//free(resultString); // ERROR?
	if (resobj == NULL) {
		return PyErr_NoMemory;
	}
	return resobj;
}


PyDoc_STRVAR(retrieveStringFromMappedFile_doc,
"retrieveStringFromMappedFile(self, startOffset:int, length:int = 0) -> bytes\n\n"
"Return a bytes object.\nBy default, return the rest of the file, starting with @startOffset.");
static PyObject *elfexmod_retrieveStringFromMappedFile(PyObject *self, PyObject *args) {
	long startOffset = 0, baseaddr = 0, mappedSize = 0;
	int len = 0;
	PyObject *selfobj = NULL;
	if (!PyArg_ParseTuple(args, "Ok|i", &selfobj, &startOffset, &len) || \
		!selfobj || \
		((baseaddr = GetElfileUnsignedLongSubVariable(selfobj, "_srcmm", "address")) == 0) || \
		((mappedSize = GetElfileUnsignedLongSubVariable(selfobj, "_srcmm", "length")) <= 0) || \
		(startOffset < 0) || (len < 0) || (len + startOffset > mappedSize)) {
		PyErr_BadArgument();
		return NULL;
	}
	if (len == 0) { /* Unchanged */
		len = mappedSize - startOffset;
	}

	PyObject *resultobj = Py_BuildValue("y#", (char*)baseaddr + startOffset, len);
	return resultobj ? resultobj : PyErr_NoMemory();
}

PyDoc_STRVAR(signFile_doc,
"signFile(self) -> bytes\n\n"
"Create a signature (in bytes object) for the file");
static PyObject *elfexmod_signFile(PyObject *self, PyObject *args) {
	int cacheline_width = 0, sign_width = 0;
	struct mmap_tuple_st srcmm = MMAP_TUPLE_INIT_VAL;
	PyObject *selfobj;
	if (!PyArg_ParseTuple(args, "Oii", &selfobj, &cacheline_width, &sign_width) || !selfobj || \
		((srcmm.address = GetElfileUnsignedLongSubVariable(selfobj, "_srcmm", "address")) == 0) || \
		((srcmm.fd = GetElfileUnsignedLongVariable(selfobj, "fileno")) < 0) \
		|| (cacheline_width <= 0) || (sign_width <= 0)) {
		PyErr_BadArgument();
		return NULL;
	}

	return elfexmod_signAux((char*)srcmm.address, elfFileLength(srcmm.fd), cacheline_width,
		sign_width, &getParityWrapper);
}

PyDoc_STRVAR(markEncrypted_doc,
"markEncrypted(self) -> bool\n\n"
"Marks the file as encrypted. Returns the *former* encryption status.");
static PyObject *elfexmod_markEncrypted(PyObject *self, PyObject *args) {
	uintptr_t addr = 0;
	PyObject *selfobj = NULL;
	if (!PyArg_ParseTuple(args, "O", &selfobj) || !selfobj || \
		((addr = GetElfileUnsignedLongSubVariable(selfobj, "_srcmm", "address")) == 0)) {
		PyErr_BadArgument();
		return NULL;
	}

	long res = semSetEncryptionMagicNumber((pointer_t)addr);
	if (res < 0) {
		return PyErr_SetFromErrno(PyExc_IOError);
	}
	return PyBool_FromLong(res);
}

PyDoc_STRVAR(mmapDealloc_doc,
"mmapDealloc(self)\n\n"
"Deallocted mmap segment, given mapped address and size.");
static PyObject *elfexmod_mmapDealloc(PyObject *self, PyObject *args) {
	uintptr_t addr = 0, file_size;
	PyObject *selfobj = NULL;
	if (!PyArg_ParseTuple(args, "O", &selfobj) || !selfobj || \
		((addr = GetElfileUnsignedLongVariable(selfobj, "address")) == 0) || \
		((file_size = GetElfileUnsignedLongVariable(selfobj, "length")) == 0)
		) {
		PyErr_BadArgument();
		return NULL;
	}
	
	if (mmap_dealloc_from_address((pointer_t)addr, file_size)) {
		return PyErr_SetFromErrno(PyExc_IOError);
	}

	Py_RETURN_NONE;
}

PyDoc_STRVAR(mmapAlloc_doc,
"mmapAlloc(self, *, writeflag:bool=False) -> typing.Tuple[int, int]\n\n"
"Allocate VM segment given file descriptor.");
static PyObject *elfexmod_mmapAlloc(PyObject *self, PyObject *args, PyObject *kywrd) {
	long fd;
	bool writeflag = false;
	const char *keywords[] = {"self", "writeflag", NULL};
	PyObject *selfobj = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kywrd, "O|b", keywords, &selfobj, &writeflag) || \
		!selfobj || ((fd = GetElfileUnsignedLongVariable(selfobj, "filedesc")) < 0)) {
		PyErr_BadArgument();
		return NULL;
	}

	void *mmap_err;
	size_t file_size;
	pointer_t addr = writeflag? \
		mmap_alloc_from_fd_writeable(fd, &file_size, &mmap_err) : \
		mmap_alloc_from_fd_readable(fd, &file_size, &mmap_err);
	if (!addr) {
		if (writeflag) {
			PyErr_Format(PyExc_EnvironmentError, "writable internal error");
		} else {
			PyErr_Format(PyExc_EnvironmentError, "readable internal error");
		}
		return NULL;
	}

	PyObject *res = Py_BuildValue("(kk)", (uintptr_t)addr, (unsigned long)file_size);
	if (!res) { // Python object allocation has failed
		mmap_dealloc_from_address(addr, file_size);
		return PyErr_NoMemory();
	}

	return res;
}

PyDoc_STRVAR(checkValidity_doc,
"checkValidity(self) -> bool\n\n"
"Verifies the file magic number is ELF's.");
static PyObject *elfexmod_checkValidity(PyObject *self, PyObject *args) {
	uintptr_t addr = 0;
	PyObject *selfobj = NULL;
	if (!PyArg_ParseTuple(args, "O", &selfobj) || !selfobj || \
		((addr = GetElfileUnsignedLongSubVariable(selfobj, "_srcmm", "address")) == 0)) {
		PyErr_BadArgument();
		return NULL;
	}

	return PyBool_FromLong(elfCheckValidity((pointer_t)addr));
}

PyDoc_STRVAR(readHeader_doc,
"readHeader(self) -> typing.Dict\n\n"
"Read the ELF header and returns its values in a dictionary.");
static PyObject *elfexmod_readHeader(PyObject *self, PyObject *args) {
	int fd;
	PyObject *selfobj = NULL;
	// Parse arguments received from the Python API
	if (!PyArg_ParseTuple(args, "O", &selfobj) || !selfobj || \
		((fd = GetElfileUnsignedLongVariable(selfobj, "fileno")) < 0)) {
		PyErr_BadArgument();
		return NULL;
	}

	Elf64_Ehdr hdr;
	long res = elfReadHeaderFromFD(fd, &hdr);
	if (res < 0) {
		if (res == (-2)) {
			PyErr_SetString(PyExc_ValueError, "Invalid header");
		} else if (res == (-3)) {
			PyErr_SetString(PyExc_ValueError, "Endiness is neither little nor big");
		} else if (res == (-4)) {
			PyErr_SetString(PyExc_ValueError, "Invalid class value");
		} else if (res == (-5)) {
			PyErr_SetString(PyExc_NotImplementedError, "File type is 64bit, but machine is 32bit");
		} else {
			return PyErr_SetFromErrno(PyExc_IOError);
		}
		return NULL;
	}

	/** Call conflicts in endiness parameter, between this machine
	and the target file*/
	int endinessFlag = hdr.e_ident[EI_DATA];
	if ((endinessFlag != 1) && (endinessFlag != 2)) {
		PyErr_SetString(PyExc_ValueError, "Endiness is neither little nor big");
		return NULL;
	}

	bool fileLittleEndianFlag = (endinessFlag == 1);
	//bool endianMismatch = fileLittleEndianFlag != elfAmILittleEndian();
	
	const char *vars[] = {"identity", "x64", "type", "machine", "version", "segments", "sections", "endiness", NULL};

	PyObject *dict = PyDict_New();
	if (dict == NULL) {
		return PyErr_SetFromErrno(PyExc_MemoryError);
	}
	
	PyObject *tmp = NULL;
	/*
	tmp = Py_BuildValue("y#", &hdr, sizeof(hdr)); // header
	if ((tmp == NULL) || PyDict_SetItemString(dict, "header", tmp)) {
		goto exrederr;
	}
	releasePyObject(tmp);
	*/

	tmp = Py_BuildValue("y#", hdr.e_ident, EI_MAG3+1); // identity
	if ((tmp == NULL) || PyDict_SetItemString(dict, vars[0], tmp)) {
		goto exrederr;
	}
	releasePyObject(tmp);

	/* Check whether format is of 32bit or 64bit
	Length of the header and its fields are affected by that attribute, specifically:
	e_entry (entry point), e_phoff, and e_shoff, are all bigger in the 64bit version.
	Later fields are shiftted accordingly.
	*/
	if ((int)hdr.e_ident[EI_CLASS] == 2) { // 64 bit
		Py_INCREF(Py_True);
		tmp = Py_True;
	} else if (((int)hdr.e_ident[EI_CLASS] == 1)) { // 32 bit
		Py_INCREF(Py_False);
		tmp = Py_False;
	}
	if ((tmp == NULL) || PyDict_SetItemString(dict, vars[1], tmp)) {
		Py_XDECREF(tmp);
		releasePyObject(dict);
		PyErr_SetString(PyExc_ValueError, "Class byte is invalid. Must be either 1 or 2\n");
		return NULL;
	}

	if (py_singleSetToDict(dict, fileLittleEndianFlag? "Little":"Big", vars[7], "z")) {
		goto exrederr;
	}

	/*Append the following values to the dictionary:
	type, machine, elf header version, program headers count, and section headers count.
	*/
	if (py_singleSetToDict(dict, hdr.e_type, vars[2], "H") || \
		py_singleSetToDict(dict, hdr.e_machine, vars[3], "H") || \
		py_singleSetToDict(dict, hdr.e_version, vars[4], "k") || \
		py_singleSetToDict(dict, hdr.e_phnum, vars[5], "k") || \
		py_singleSetToDict(dict, hdr.e_shnum, vars[6], "k") \
		) {
		goto exrederr;
	}

	return dict;

exrederr:
	if (dict) {
		releasePyObject(dict);
	}
	return PyErr_SetFromErrno(PyExc_MemoryError);
}

PyDoc_STRVAR(readSegmentsTable_doc,
"readSegmentsTable(self, fileEncodedInLittleEndian:bool) -> typing.List\n\n"
"Returns a sequence with the dictionaries as its lines, of the segments table");
static PyObject *elfexmod_readSegmentsTable(PyObject *self, PyObject *args) {
	PyObject *selfobj = NULL;
	uintptr_t addr = 0;
	bool littleEndianFormat;
	
	if (!PyArg_ParseTuple(args, "Ob", &selfobj, &littleEndianFormat) || !selfobj || \
		((addr = GetElfileUnsignedLongSubVariable(selfobj, "_srcmm", "address")) == 0)) {
		PyErr_BadArgument();
		return NULL;
	}

	Elf_segment_header **segtable = elfGetSegmentHeadersPointers(addr);
	if (!segtable) {
		PyErr_SetString(PyExc_IOError, "Failed to extract segment table from file");
		return NULL;
	}
	const char *keys[] = {"type", "offset", "vaddr", "paddr", "filesize", "memorysize", "flags", NULL};

	PyObject *list = PyList_New(0);
	if (list == NULL) {
		goto excrsta0;
	}

	bool endianMismatch = elfEndinessConflict(addr);
	bool flag64BitHeader = elfIsHeaderType64Class(addr);
	PyObject *line = NULL;
	for (int i =0; segtable[i]; ++i) {
		if ((line = PyDict_New()) == NULL) {
			goto excrsta1;
		}

		if (flag64BitHeader) {
			if (endianMismatch) {
				char longstring[sizeof(long)], intstring[sizeof(int)];
				if ( \
					py_singleSetToDict(line, *swap4bytes(intstring, &(((Elf64_Phdr*)segtable[i])->p_type)), keys[0], "k") || // word type
					py_singleSetToDict(line, *swapBytesEndian(longstring, &(((Elf64_Phdr*)segtable[i])->p_offset), sizeof(long)), keys[1], "k") || // offset type
					py_singleSetToDict(line, *swapBytesEndian(longstring, &(((Elf64_Phdr*)segtable[i])->p_vaddr), sizeof(long)), keys[2], "k") || // address type
					py_singleSetToDict(line, *swapBytesEndian(longstring, &(((Elf64_Phdr*)segtable[i])->p_paddr), sizeof(long)), keys[3], "k") || // address type
					py_singleSetToDict(line, *swap4bytes(intstring, &(((Elf64_Phdr*)segtable[i])->p_filesz)), keys[4], "k") || // word type
					py_singleSetToDict(line, *swap4bytes(intstring, &(((Elf64_Phdr*)segtable[i])->p_memsz)), keys[5], "k") || // word type
					py_singleSetToDict(line, *swap4bytes(intstring, &(((Elf64_Phdr*)segtable[i])->p_flags)), keys[6], "k") // word type
				) {
					goto excrsta2;
				}
			} else {
				if ( \
					py_singleSetToDict(line, ((Elf64_Phdr*)segtable[i])->p_type, keys[0], "k") || // word type
					py_singleSetToDict(line, ((Elf64_Phdr*)segtable[i])->p_offset, keys[1], "k") || // offset type
					py_singleSetToDict(line, ((Elf64_Phdr*)segtable[i])->p_vaddr, keys[2], "k") || // address type
					py_singleSetToDict(line, ((Elf64_Phdr*)segtable[i])->p_paddr, keys[3], "k") || // address type
					py_singleSetToDict(line, ((Elf64_Phdr*)segtable[i])->p_filesz, keys[4], "k") || // word type
					py_singleSetToDict(line, ((Elf64_Phdr*)segtable[i])->p_memsz, keys[5], "k") || // word type
					py_singleSetToDict(line, ((Elf64_Phdr*)segtable[i])->p_flags, keys[6], "k") // word type
				) {
					goto excrsta2;
				}
			}
		} else {
			if (endianMismatch) {
				char tmpstring[sizeof(int)];
				if ( \
					py_singleSetToDict(line, *swap4bytes(tmpstring, &(((Elf32_Phdr*)segtable[i])->p_type)), keys[0], "I") || // word type
					py_singleSetToDict(line, *swap4bytes(tmpstring, &(((Elf32_Phdr*)segtable[i])->p_offset)), keys[1], "I") || // offset type
					py_singleSetToDict(line, *swap4bytes(tmpstring, &(((Elf32_Phdr*)segtable[i])->p_vaddr)), keys[2], "I") || // address type
					py_singleSetToDict(line, *swap4bytes(tmpstring, &(((Elf32_Phdr*)segtable[i])->p_paddr)), keys[3], "I") || // address type
					py_singleSetToDict(line, *swap4bytes(tmpstring, &(((Elf32_Phdr*)segtable[i])->p_filesz)), keys[4], "I") || // word type
					py_singleSetToDict(line, *swap4bytes(tmpstring, &(((Elf32_Phdr*)segtable[i])->p_memsz)), keys[5], "I") || // word type
					py_singleSetToDict(line, *swap4bytes(tmpstring, &(((Elf32_Phdr*)segtable[i])->p_flags)), keys[6], "I") // word type
				) {
					goto excrsta2;
				}
			} else {
				if ( \
					py_singleSetToDict(line, ((Elf32_Phdr*)segtable[i])->p_type, keys[0], "I") || // word type
					py_singleSetToDict(line, ((Elf32_Phdr*)segtable[i])->p_offset, keys[1], "I") || // offset type
					py_singleSetToDict(line, ((Elf32_Phdr*)segtable[i])->p_vaddr, keys[2], "I") || // address type
					py_singleSetToDict(line, ((Elf32_Phdr*)segtable[i])->p_paddr, keys[3], "I") || // address type
					py_singleSetToDict(line, ((Elf32_Phdr*)segtable[i])->p_filesz, keys[4], "I") || // word type
					py_singleSetToDict(line, ((Elf32_Phdr*)segtable[i])->p_memsz, keys[5], "I") || // word type
					py_singleSetToDict(line, ((Elf32_Phdr*)segtable[i])->p_flags, keys[6], "I") // word type
				) {
					goto excrsta2;
				}
			}
		}

		if (PyList_Append(list, line)) {
			goto excrsta2;
		}

		releasePyObject(line);
	}

	free(segtable);
	return list;
excrsta2:
	releasePyObject(line);
excrsta1:
	if (list) {
		releasePyObject(list);
	}
excrsta0:
	free(segtable);
	return PyErr_SetFromErrno(PyExc_MemoryError);
}

/*
=============================================================================
                        		Python's C API Code
=============================================================================
*/

static PyMethodDef exmod_methods[] = {
	/* "Python name"   c-func name   argument_repr    desc. */
	{"retrieveStringFromMappedFile", elfexmod_retrieveStringFromMappedFile, METH_VARARGS, retrieveStringFromMappedFile_doc},
	{"mmapAlloc", elfexmod_mmapAlloc, METH_VARARGS | METH_KEYWORDS, mmapAlloc_doc},
	{"mmapDealloc", elfexmod_mmapDealloc, METH_VARARGS, mmapDealloc_doc},
	{"checkValidity", elfexmod_checkValidity, METH_VARARGS, checkValidity_doc},
	{"readHeader", elfexmod_readHeader, METH_VARARGS, readHeader_doc},
	{"readSegmentsTable", elfexmod_readSegmentsTable, METH_VARARGS, readSegmentsTable_doc},
	{"isEncrypted", elfexmod_isEncrypted, METH_VARARGS, isEncrypted_doc},
	{"isStaticallyLinkedExecutable", elfexmod_isStaticallyLinkedExecutable, METH_VARARGS, isStaticallyLinkedExecutable_doc},
	{"markEncrypted", elfexmod_markEncrypted, METH_VARARGS, markEncrypted_doc},
	{"trimSections", elfexmod_trimSections, METH_VARARGS, trimSections_doc},
	{"fileLength", elfexmod_fileLength, METH_VARARGS, fileLength_doc},
	{"fileHeaderLength", elfexmod_fileHeaderLength, METH_VARARGS, fileHeaderLength_doc},
	{"nullifyDomains", elfexmod_nullifyDomains, METH_VARARGS, nullifyDomains_doc},
	{"appendLandlords", elfexmod_appendLandlords, METH_VARARGS, appendLandlords_doc},
	{"encBytesArray", elfexmod_encBytesArray, METH_VARARGS, encBytesArray_doc},
	{"signBytesArray", elfexmod_signBytesArray, METH_VARARGS, signBytesArray_doc},
	{"signFile", elfexmod_signFile, METH_VARARGS, signFile_doc},
	{NULL, NULL, 0, NULL}
};

static struct PyModuleDef elfexmodule = {
	PyModuleDef_HEAD_INIT,
	"elfexmod", //name
	NULL, //module doc
	-1, //status in global variables
	exmod_methods
};

PyMODINIT_FUNC PyInit_elfexmod(void){
	PyObject *obj = NULL;
	if (!(obj = PyModule_Create(&elfexmodule))){
		return NULL;
	}

	ExmodError = PyErr_NewException("exmod.error", NULL, NULL);
	Py_INCREF(ExmodError);
	PyModule_AddObject(obj, "error", ExmodError);
	return obj;
}

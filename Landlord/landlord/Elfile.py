#!/usr/bin/env python3

__author__ = "bawplayer"

import elfexmod
from collections import namedtuple
import typing
from enum import IntEnum
import logging
from sys import stderr


def getEnumNameMatch(enumclass, val):
	"""Returns the first value.
	"""
	for e in enumclass:
		if e.value == val:
			return e.name

class Elfile:
	#: Meaningful fields of segment-headers as detailed in ELF header
	ElfSegmentHeader = namedtuple("ElfSegmentHeader", ["offset", "vaddress", "size", "footprint"])
	#: Utility type to hint function argument type of :py:data:`ElfSegmentHeader`
	ElfSegHeaderType = typing.NewType("ElfSegHeaderType", ElfSegmentHeader)

	class MachineCodes(IntEnum):
		SPARC = 0x02
		x86 = 0x03
		MIPS = 0x08
		SPARCV8PLUS = 0x12
		PowerPC = 0x14
		ARM = 0x28
		SPARCV9 = 0x2B
		IA64 = 0x64
		x64 = 0x3E
		AArch64 = 0xB7

	class SegmentHeaderTypes(IntEnum):
		NULL = 0x0
		LOAD = 0x1
		DYNAMIC = 0x2
		INTERP = 0x3
		NOTE = 0x4
		SHLIB = 0x5
		PHDR = 0x6

	class FileTypes(IntEnum):
		NONE = 0
		REL = 1 # Relocatable
		EXEC = 2 # Executable
		DYN = 3 # Shared object
		CORE = 4

	class Mmap:
		def __init__(self, f, writable:bool = True):
			if f.closed:
				raise ValueError("parameter must be an opened file")
			self.filedesc = f.fileno()
			try:
				self.address, self.length = elfexmod.mmapAlloc(self, writeflag=writable)
			except:
				logging.debug("Inner function failed.\nfiledesc={}".format(self.filedesc))
				raise
			if (self.address == 0):
				raise IOError("mmap failed")
			if self.length == 0:
				raise IOError("File came up empty")

		def __del__(self):
			elfexmod.mmapDealloc(self)

		def __len__(self) -> int:
			"""Original allocated length.
			"""
			return self.length

	def elfIsValid(barray:typing.Union[bytes, bytearray]) -> bool:
		"""Validates the file's magic number.
		"""
		mnumber = b'\x7fELF'
		if not isinstance(barray, (bytes, bytearray)):
			raise TypeError("argument must be of type bytes/bytearray")
		elif (len(barray) < 4):
			raise ValueError("argument is too short")
		return barray[:4] == mnumber

	def signContent(content:bytes, *, cacheline_width = 16, sign_width = 1, padContent:bool = False) -> bytes:
		"""Return byte array with the corresponding parity bits.
		The expected result's length is calculated: len(content)*sign_width/cacheline_width
		"""
		if not isinstance(content, bytes):
			raise TypeError("content must be of type bytes")
		elif len(content) == 0:
			return bytes() # empty
		if padContent and (len(content) % cacheline_width != 0):
			padding_length = len(content) + cacheline_width - (len(content)%cacheline_width)
			return elfexmod.sign(content.rjust(padding_length, b'\0'), cacheline_width, sign_width)
		return elfexmod.signBytesArray(content, cacheline_width, sign_width)

	def __init__(self, filename:str, *, writable:bool=True):
		if not writable:
			raise NotImplementedError("file must be writable")
		self.srcfilename = filename
		self.writable = writable
		# self._srcfile = open(self.srcfilename, "wb" if self.writable else "rb+")
		self._srcfile = open(self.srcfilename, "r+b")
		self.name = self._srcfile.name
		self.fileno = self._srcfile.fileno()
		self._srcmm = Elfile.Mmap(self._srcfile, writable=True)
		if not elfexmod.checkValidity(self):
			raise TypeError("Not an ELF file")
		self.header_dict = None
		self.segments_table = None

	def __del__(self):
		try:
			if self._srcmm:
				del(self._srcmm) # must come first
		except AttributeError:
			pass
		try:
			if self._srcfile:
				self._srcfile.close()
		except AttributeError:
			pass

	def __enter__(self):
		return self

	def __exit__(self, type, value, traceback):
		pass

	def __len__(self):
		"""Returns the file's length.
		"""
		return len(self._srcmm)

	def __str__(self):
		from os.path import basename
		def _getFileTypeStr(t:int) -> str:
			if t == Elfile.FileTypes.EXEC:
				return "Executable"
			elif t == Elfile.FileTypes.DYN:
				return "Shared library"
			else:
				return getEnumNameMatch(Elfile.FileTypes, hdrdict["type"])
		strargs = list()
		try:
			strargs.append(basename(self.srcfilename))
			hdrdict = self.readHeader()
			strargs[0] += " ({})".format(_getFileTypeStr(hdrdict["type"]))
			if not Elfile.elfIsValid(hdrdict["identity"]):
				strargs.append("Invalid ELF Header")
			else:
				strargs.append("Segments #: {}".format(hdrdict["segments"]))
				strargs.append("Sections #: {}".format(hdrdict["sections"]))
				strargs.append("Machine type: {} ({}-endian encoding, {}bit)".format(
					getEnumNameMatch(Elfile.MachineCodes, hdrdict["machine"]),
					hdrdict["endiness"],
					"64" if hdrdict["x64"] else "32"
				))
				if self.isExecutable():
					strargs.append("Linkage type: {}".format(
						"Static" if self.isStaticallyLinkedExec() else "Dynamic")
					)
		except:
			pass
		return "\n".join(strargs)

	def __bool__(self):
		"""Revarifies the header.
		"""
		return (len(self) > 0) and elfexmod.checkValidity(self)

	def isExecutable(self) -> bool:
		return self.readHeader(force=False)['type'] == Elfile.FileTypes.EXEC.value

	def isStaticallyLinkedExec(self) -> bool:
		"""Returns True if executable and none of the program (segment) headers is of type
		:py:class:`Elfile.SegmentHeaderTypes.INTERP` (interpreter).
		Raise ValueError if file has no segments.
		see: :py:func:`elfexmod.isStaticallyLinkedExecutable`
		"""
		return elfexmod.isStaticallyLinkedExecutable(self)

	def _setEncryptedAttribute(self) -> bool:
		"""Marks the file as encrypted and returns the *original* state.
		"""
		assert self.writable, "File is set for read mode"
		return elfexmod.markEncrypted(self)

	def getEncryptedAttribute(self) -> bool:
		"""Returns current encryption state.
		"""
		return elfexmod.isEncrypted(self)

	def trimSectionTable(self, clonename):
		"""Create a clone to the source ELF file.
		The section table will be trimmed from the clone.
		"""
		elfexmod.trimSections(self, clonename)		

	def encrypt(self, conver, cloneName:typing.Optional[str]=None, *, overwrite:bool=True) -> str:
		"""Generates a file with ".sec" extension, with the signatures of the
		original content of the file following the data as a separate segment.
		Basically, it calls semAppendLandlordSegment that does it all.
		Encryption is yet to be implemented.
		"""
		from os.path import exists
		if cloneName is None:
			cloneName = self._srcfile.name + ".sec"
		if cloneName == self._srcfile.name:
			raise FileExistsError("Cannot clone with the same filename as source.")
		if (not overwrite) and exists(cloneName):
			raise FileExistsError("File already exists. (Try a different cloneName)")
		assert self.isStaticallyLinkedExec(), "File must be statically linked"
		elfexmod.appendLandlords(self, cloneName, \
			conver.landlord_base_ptr, conver.tree_size)
		self._setEncryptedAttribute()
		return cloneName

	def readHeader(self, *, force:bool=False) -> typing.Dict:
		"""Returns the principle ELF header of the file using
		:py:func:`elfexmod.readHeader`.
		Set @force to force re-read of the file.
		"""
		if force or (not hasattr(self, "header_dict")) or (self.header_dict is None):
			self.header_dict = elfexmod.readHeader(self)
		return self.header_dict

	def readSegmentTable(self, *, force:bool=False, excludeEmpty:bool=False) -> typing.List[typing.Dict]:
		"""Reads the segment table from the file, using
		:py:func:`elfexmod.readSegmentsTable`.
		If the file doesn't have a segment table, it raises ValueErr.
		"""
		if (self.header_dict is None) or force:
			self.readHeader(force=force)
		if force or (not hasattr(self, "segments_table")) or (self.segments_table is None):
			if self.header_dict["segments"] == 0:
				raise ValueError("file has no segment table")
			self.segments_table = elfexmod.readSegmentsTable(self,
				self.header_dict["endiness"].lower() == "little")
		if not excludeEmpty:
			return self.segments_table
		else:
			return [s for s in self.segments_table if s["memorysize"]>0]

	def readSegmentHeaders(self, *, excludeEmpty:bool=False) -> typing.List[ElfSegHeaderType]:
		"""Using :py:func:`readSegmentTable`.
		When @excludeEmpty is True, excludes segments that their process'
		initial footprint is marked as empty.
		"""
		return list(map(
			lambda s: Elfile.ElfSegmentHeader(s["offset"], s["vaddr"], s["filesize"], s["memorysize"]),
			self.readSegmentTable(excludeEmpty=excludeEmpty))
		)

	def headerTotalSize(self):
		"""Returns the size(ELF_HEADER) + size(Segment Headers Table).
		Using :py:func:`elfexmod.fileHeaderLength`
		"""
		return elfexmod.fileHeaderLength(self)
	
	def matchLineToAddress(self):
		"""Deduces the virtual address each byte in the executable
		is mapped to.
		Returns a dictionary:
		key - Offset within the file
		item - List of virtual addresses
		"""
		def _isInSegment(offset:int, segment:Elfile.ElfSegHeaderType) -> bool:
			"""Checks whether a specific byte in the ELF file is contained
			within a given segment.
			"""
			return (0 <= (offset - segment.offset) < segment.size)
		def _getVirAddress(offset:int, segment:Elfile.ElfSegHeaderType):
			"""Returns the virtual address of a byte, relative to a segment.
			"""
			relativeOffset = offset - segment.offset
			if not _isInSegment(offset, segment):
				return None
			return relativeOffset + segment.vaddress
		segmentsHeaders = self.readSegmentHeaders(excludeEmpty=True)
		matches = {}
		for offset in range(len(self)):
			addresses = list() # initialize list
			for seg in segmentsHeaders:
				if _isInSegment(offset, seg):
					addresses.append(_getVirAddress(offset, seg))
			matches[offset] = set(addresses) # insert
		return matches

	def nullifyUnmappedBytes(self):
		"""Nullify bytes in the file which have no virtual address
		attached to them.
		"""
		from collections import namedtuple
		Domain = namedtuple("Domain", ["base", "size"])
		def _groupInDomains(offsets:List[int]):
			domains = []
			currBase, currLength = 0,0
			elementsCount = 0
			for o in offsets:
				if (o == currBase + currLength):
					currLength += 1
					continue
				elif currLength > 0:
					domains.append(Domain(self._srcmm.address+currBase, currLength))
				currBase = o
				currLength = 1
			if currLength > 0:
				domains.append(Domain(self._srcmm.address+currBase, currLength))
			return domains
		notmapped = list()
		matches = self.matchLineToAddress()
		headerTotalSize = self.headerTotalSize()
		for k,v in matches.items():
			if k < headerTotalSize:
				# never remove header
				continue
			if not v:
				# set of virtual addresses is empty
				notmapped.append(k)
		notmapped.sort()
		elfexmod.nullifyDomains(_groupInDomains(notmapped))

	def findBytesConflicts(self):
		"""Returns only lines that are mapped for more than a single address.
		"""
		resdict = {}
		for k,v in self.matchLineToAddress().items():
			if len(v) > 1:
				resdict[k] = v # insert to resdict
		return resdict

	def findAddressesConflicts(self):
		"""Returns a list of virtual addresses whom have more than a
		single byte candidate to occupy it.
		!TODO: Optimization is required here
		"""
		matches = self.matchLineToAddress()
		conflicts, sofar = list(), list()
		for v in matches.values():
			for address in v:
				if address in sofar:
					conflicts.append(address)
				else:
					sofar.append(address)
		return set(conflicts.sort()) if conflicts else set()

	def generateLandlords(self, conver, *, ignoreBlankLandlords:bool=True) -> typing.Dict:
		"""Generates a byte stream with the parity signature of the file.
		See: :py:func:`semGetParity`
		Returns an iterator to a dictionary.
		The function will fail if multiple lines share the same target-process'
		virtual address, or multiple "segments" share the same cacheline with
		a gap.
		e.g. 1st - 0x1000-0x1009 , 2nd - 0x100B - 0x100F 
		(note that 0x100A isn't mapped by neither)
		"""
		SegmentMetaDataTuple = namedtuple("SegmentMetaDataTuple", ["s_offset", "s_addr", "e_offset", "e_addr"])
		SegmentMetaDataTupleType = typing.NewType("SegmentMetaDataTupleType", SegmentMetaDataTuple)
		def _findConsecutiveAddressses(self) -> typing.List[SegmentMetaDataTupleType]:
			"""Translates the file to "segments", to allow efficient signing
			of its content.
			"""
			if self.findBytesConflicts() or self.findAddressesConflicts():
				raise ValueError("Conflict(s) found")
			matches = self.matchLineToAddress() # dictionary
			sortedMatches = sorted(matches.items(), key=lambda x: x[1]) # sort by value

			currentBottomOffset, lastOffset = 0,0
			currentBottomVaddr, lastVaddr = 0,0
			res = list() # init
			for offset, vaddr in sortedMatches:
				if not vaddr:
					continue
				vaddr = list(vaddr)[0]
				if lastVaddr == 0:
					currentBottomOffset = lastOffset = offset
					currentBottomVaddr = lastVaddr = vaddr
					continue
				if (lastOffset != offset-1) or (lastVaddr != vaddr-1):
					res.append(SegmentMetaDataTuple(currentBottomOffset, currentBottomVaddr, offset, vaddr))
					lastVaddr = 0
				else:
					lastOffset, lastVaddr = offset, vaddr
			if (lastVaddr != 0):
				res.append(SegmentMetaDataTuple(currentBottomOffset, currentBottomVaddr, lastOffset, lastVaddr))
			if not res: # empty
				raise ValueError("File is empty")
			return res

		def _checkCachelineOvelapping(addresses:typing.List[typing.Tuple[int,int]], cacheline_width:int) -> bool:
			"""Returns False if no two segments share the same cacheline.
			"""
			lastUpperBound = 0
			for low,up in addresses:
				if lastUpperBound == 0:
					lastUpperBound = up
					continue
				if lastUpperBound >= low:
					return True
				if ((lastUpperBound + 1) % cacheline_width) != 0:
					#: incmod - increment modulo cacheline_width -1
					#; e.g. val=16 with cacheline_width=16, turns to 31
					#: e.g. val=40 with cacheline_width=16, turns to 47
					incmod = lambda x,m: x + m - ((x%m) + 1)
					if incmod(lastUpperBound, cacheline_width) >= low:
						logging.debug("Although, cacheline overlapping, no segments overlapping")
						return True
				lastUpperBound = up
				assert lastUpperBound > 0, 'woops'
			return False

		def _fillToAlignWithCacheline(baseaddr:int, array:bytes, cacheline_width:int, filler:bytes=b'\0') -> bytes:
			if (baseaddr % cacheline_width != 0):
				array = array.ljust(len(array) + (baseaddr % cacheline_width), filler)
				baseaddr -= (baseaddr % cacheline_width)
			if (len(array) % cacheline_width) != 0:
				array = array.rjust(
					len(array) + (cacheline_width - (len(array) % cacheline_width)),
					filler)
			return array

		def _createSignaturesDict(segments:typing.Dict[int, bytes],
			*, fillToAlign:bool=True) -> typing.Dict:
			"""Returns a dictionary, with the source's base address as its keys,
			and the landlords' content - as the item.
			By default - both the baseaddr (read, dictionary's keys) and the
			signatures (items) are cache-aligned.
			"""
			signaturesDict = dict()
			for addr, content in segments.items():
				if fillToAlign:
					content = _fillToAlignWithCacheline(
						addr, # virtual address
						content, # content
						cacheline_width
					)
				_sign = elfexmod.signBytesArray(
					content,
					cacheline_width,
					sign_width
				) # end of signBytesArray()
				if fillToAlign:
					assert (len(_sign) % sign_width == 0)
					baseSourceAddress = addr - (addr % cacheline_width)
				landlordAddress = conver.getLandlordIndex(baseSourceAddress).address
				for i in range(len(_sign)):
					if ((i % sign_width) == 0) and (i > 0):
						landlordAddress += landlord_width
					signaturesDict[landlordAddress + (i % sign_width)] = _sign[i]
				logging.debug("source address: {}, content: {}, landlord address: {}, #sign: {}".format(
					addr, content, landlordAddress, len(_sign)))
			return signaturesDict

		def _createSignaturesDictFromSource(self,
			segmentList:typing.List[SegmentMetaDataTupleType]) -> typing.Dict:
			"""Retrieve strings from source file, and generate a dictionary
			that contains the source's signature.
			"""
			srcStringsDict = dict()
			for st in segmentList:
				srcString = elfexmod.retrieveStringFromMappedFile(
					self,
					st.s_offset,
					(st.e_addr - st.s_addr + 1) # length
				)
				srcStringsDict[st.s_addr] = srcString
			return _createSignaturesDict(srcStringsDict, fillToAlign=True)

		def _createLandlordSignature(landlords:typing.Dict) -> typing.Dict:
			"""Assumes that lowest-level landlords has signature
			that is different from None.
			"""
			def _createLandlordSignatureAux(addr:int):
				if landlords[addr] is not None:
					# valid value
					return
				# otherwise, current value is dummy and should be replaced with a signature
				srcAddress = conver.getAddressFromLandlordAddress(addr)
				srcContent = list()
				for i in range(cacheline_width):
					_curr = srcAddress+i
					if _curr not in landlords:
						srcContent.append(0)
					else:
						_createLandlordSignatureAux(_curr)
						srcContent.append(landlords[_curr])
				try:
					sign = elfexmod.signBytesArray(bytes(bytearray(srcContent)),
						cacheline_width, sign_width)
				except:
					logging.debug("source content is: {}".format(srcContent))
					logging.debug("bytes content is: {}".format(bytearray(srcContent)))
					raise
				assert (len(sign) <= sign_width)
				for i in range(len(sign)):
					landlords[addr + i] = sign[i]

			# _createLandlordSignature() starts here:
			for k in list(landlordsDict):
				# traverse up the tree (leaves-to-root), using dummy values for signatures
				for ll in conver.getLandlordBranch(k, 1):
					if ll.address not in landlordsDict:
						landlordsDict[ll.address] = None
			for k in list(landlords):
				# traverse the opposite direction to fill with valid signatures
				_createLandlordSignatureAux(k)
			return landlords

		def _extractAddresses(segList:typing.List[SegmentMetaDataTuple]) -> typing.List[typing.Tuple[int,int]]:
			res = list()
			for smdt in segList:
				res.append((smdt.s_addr, smdt.e_addr))
			return res

		# generateLandlords() starts here, with some type checking
		if conver is None:
			raise TypeError("@conver must not be None")
		if (conver.program_cache_line_size_log != conver.landlord_cache_line_size_log):
			raise NotImplementedError("current implementation assumes caches share similar configuration")
		cacheline_width = 2**conver.program_cache_line_size_log
		if (conver.signature_size_in_bits % 8):
			raise NotImplementedError("signature size must be divisable by 8")
		sign_width = conver.signature_size_in_bits // 8
		landlord_width = 2**conver.landlord_size_log

		# the actual code starts here
		segmentTupleList = _findConsecutiveAddressses(self) # seqence of type SegmentMetaDataTuple
		if _checkCachelineOvelapping(_extractAddresses(segmentTupleList), cacheline_width):
			raise ValueError("Segments overlap")
		landlordsDict = _createSignaturesDictFromSource(self, segmentTupleList)
		landlordsDict = _createLandlordSignature(landlordsDict)

		# filter blank landlords
		return {k:v for k,v in landlordsDict.items() if (v != 0) or not ignoreBlankLandlords}
		
#END OF ELFILE CLASS

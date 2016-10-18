#landlord converter api
from sys import stderr
from collections import namedtuple
import typing
import logging

def clog2(x):
	from math import ceil, log2
	return ceil(log2(x))

def clog2_func_wrapper(func):
	def inner(*args, **kwargs):
		import math
		return clog2(func(*args, **kwargs))
	return inner

def isninstance(x, t) -> bool:
	"""Return is either equivalent to None, or instance of type t
	"""
	return (x is None) or isinstance(x, t)

def relaxhex(x:int, glimit:int=100) -> str:
	"""relaxhex() is a relaxed version of hex(),
	it translates only values greater than @glimit.
	"""
	return hex(x) if x>=glimit else str(x)

def isPowerOf2(x:int) -> bool:
	if not isinstance(x, int):
		return False
	while (x > 0):
		if (x%2 != 0): # odd
			return (x == 1)
		x >>= 1 # shift right
	return False


class LandlordConverter():
	LandlordCoordinates = namedtuple("LandlordCoordinates", ["segment_offset", "layer_number", "rel_index", "address"])
	LandlordCoorType = typing.NewType("LandlordCoorType", LandlordCoordinates)

	class InvalidAddressError(TypeError):
		def __init__(self, message="", addr:int=0):
			super().__init__(message)
			self.addr = addr

	def __str_hr_log(log2_x:int) -> str:
		"""Convert integer to human readable string.
		Argument is a the log.
		"""
		measuresNames = ["bytes", "KB", "MB", "GB", "TB", "PB"]
		for i in range(len(measuresNames)):
			if (log2_x <= (i + 1) * 10):
				return str(2**(log2_x - i*10)) + " " + measuresNames[i]
		return str(2**(log2_x - len(measuresNames)*10)) + " " + measuresNames[-1]

	def __str_hr(x:int) -> str:
		"""Convert integer to human readable string.
		"""
		measuresNames = ["bytes", "KB", "MB", "GB", "TB", "PB"]
		val = x
		step = 10
		for m in measuresNames:
			tmp = val >> step
			if (tmp == 0):
				return "{} {}".format(val, m)
			if (val % (2**step) != 0):
				tmp += 1
			val = tmp
		return "{} {}".format(val, measuresNames[-1])

	def getAlphaLayerSize(self) -> int:
		return self._getLandlordLayerSize(self._calcLandlordLayersCount()-1)		

	def isAddressAligned(self, addr:int) -> bool:
		"""Landlord cacheline size must be equal to data cache line size.
		"""
		cachelineSize = self.program_cache_line_size_log \
			if self._isDataAddress(addr) \
			else self.landlord_cache_line_size_log
		return (addr % 2**self.program_cache_line_size_log) == 0

	def isValidAddress(self, addr:int, *, performIsAlignedCheck:bool=False) -> bool:
		"""isValidAddress() returns True if address is within the given domain.
		A valid address could be any byte within the domain.
		"""
		if (not isinstance(addr, int)) or (addr < 0):
			raise TypeError("@addr ({}) must be natural integer".format(addr))
		if performIsAlignedCheck:
			if not isAddressAligned(addr):
				return False
		return (addr < 2**self.domain_log)

	def _isKernelAddress(self, addr:int) -> bool:
		if self.kernel_base_addr is None:
			# No dedicated kernel segment
			return False
		return self.isValidAddress(addr) and (addr >= self.kernel_base_addr)

	def _isDataAddress(self, addr:int) -> bool:
		return (
				(addr < self.landlord_base_ptr) or
				(addr >= self.landlord_base_ptr + self.tree_size)
			) and (addr < 2**self.domain_log) and \
			not self._isKernelAddress(addr)

	def isValidDataAddress(self, addr:int) -> bool:
		return self.isValidAddress(addr) and self._isDataAddress(addr)

	def isValidLandlordAddress(self, addr:int) -> bool:
		return self.isValidAddress(addr) and \
			not self._isDataAddress(addr) and \
			not self._isKernelAddress(addr)

	def _dataCachelineAlign(self, addr:int) -> bool:
		return addr & -(2**self.program_cache_line_size_log)

	def _landlordCachelineAlign(self, addr:int) -> bool:
		return addr & -(2**self.landlord_cache_line_size_log)

	def _isCachelineAligned(self, addr:int) -> bool:
		if self.isValidDataAddress(addr):
			return self._dataCachelineAlign(addr)
		elif self.isValidLandlordAddress(addr):
			return self._landlordCachelineAlign(addr)
		raise InvalidAddressError()

	def __init__(self, domain_log:int, alpha_ll_max_size_in_bytes:int,
		cache_line_size_log:int, landlord_size_log:int=2,
		signature_size_in_bits:typing.Optional[int] = None,
		*, ll_base_ptr:int=0, kernel_base_addr:typing.Optional[int]=None):
		"""By default, signature size is set to program_cacheline_size//8.
		Argument cache_line_size_log sets both program cache and landlord cache
		line-size, in order te ease the class's implementation.
		Note that the signature is included within each landlord.
		signature_size defaults at cacheline-size / 8 (bit per byte)
		"""
		if not isinstance(domain_log, int) or not isinstance(ll_base_ptr, int) \
			or not isinstance(alpha_ll_max_size_in_bytes, int) or not isinstance(cache_line_size_log, int) \
			or not isinstance(landlord_size_log, int) or not isninstance(cache_line_size_log, int):
			raise ValueError("All values must be integers")
		self.domain_log = domain_log
		self.landlord_base_ptr = ll_base_ptr
		self.alpha_ll_size_log = clog2(alpha_ll_max_size_in_bytes)
		self.program_cache_line_size_log = cache_line_size_log
		
		self.kernel_base_addr = kernel_base_addr

		#: landlord cache line size is set to match the program's one
		#: in order to ease implementation
		self.landlord_cache_line_size_log = self.program_cache_line_size_log
		self.landlord_size_log = landlord_size_log
		assert (self.landlord_base_ptr % (2**self.program_cache_line_size_log) == 0)
		# assert (self.landlord_base_ptr % (2**self.landlord_cache_line_size_log) == 0)

		#: how many landlords are in cache line
		self.landlord_cache_line_capacity_log = \
			self.landlord_cache_line_size_log - self.landlord_size_log
		assert self.landlord_cache_line_capacity_log > 0, \
			"Landlord cache line size ({}) is too small".format(self.landlord_cache_line_capacity_log)
		assert(self.landlord_cache_line_capacity_log >= 1)
		if (self.domain_log is not None) and (self.domain_log < 0):
			raise TypeError("domain_log must be natural integer")

		# alpha landlord contains at least a single landlord
		assert(self.alpha_ll_size_log >= self.landlord_size_log)
		self.tree_size = self._calcTreeSize(include_root_layer=True)
		if (clog2(self.getAlphaLayerSize()) > alpha_ll_max_size_in_bytes):
			raise AssertionError("{} ({}) is smaller than {} ({})".format(
				"alpha layer size log",
				self.getAlphaLayerSize(),
				"alpha layer max size log",
				alpha_ll_max_size_in_bytes
				)
			)
		self.landlordLayersCount = self._calcLandlordLayersCount()

		assert  (2**self.domain_log >= self.landlord_base_ptr + self.tree_size)
		# if self.kernel_base_addr is None:
		# 	self.kernel_base_addr = 2**(self.domain_log - 1)
		if self.kernel_base_addr is not None:
			assert (self.kernel_base_addr < (2**self.domain_log))
			assert (self.kernel_base_addr >= self.landlord_base_ptr + self.tree_size)

		# signature size
		if signature_size_in_bits is None:
			# signature bit per byte in cache line
			self.signature_size_in_bits = (2**self.program_cache_line_size_log)
		else:
			self.signature_size_in_bits = signature_size_in_bits
		if (not isinstance(self.signature_size_in_bits, int)) or (self.signature_size_in_bits < 0):
			raise ValueError("signature size must be positive integer")
		elif (self.signature_size_in_bits == 0):
			logging.warning("No signature")
			raise ValueError("signature size must be greater than zero")
		if ((self.signature_size_in_bits // 8) > \
			2**min(self.program_cache_line_size_log, self.landlord_cache_line_size_log)):
			raise ValueError("signature size ({}b) is too small".format(self.signature_size_in_bits))

	def __str__(self) -> str:
		strlist = list()
		strlist.append("Effective domain range is: {}".format(LandlordConverter.__str_hr(2**self.domain_log - self.tree_size)))
		if (self.program_cache_line_size_log != self.landlord_cache_line_size_log):
			strlist.append("Data cache line size: {} bytes".format(2**self.program_cache_line_size_log))
			strlist.append("Landlord cache line size: %s bytes" % (2**self.landlord_cache_line_size_log))
		else:
			strlist.append("Data & Landlord cache line size: {}".format(
				LandlordConverter.__str_hr_log(self.program_cache_line_size_log)))
		if (self.landlord_base_ptr != 0):
			strlist.append("Landlord pointer is: {}".format(hex(self.landlord_base_ptr)))
		strlist.append("Alpha-landlord layer size is: " + LandlordConverter.__str_hr_log(clog2(self.getAlphaLayerSize())))
		strlist.append("Tree size is: {} bytes ({})".format(self.tree_size, LandlordConverter.__str_hr(self.tree_size)))
		strlist.append("Single landlord width is: {tot} bits\n(lower {sig} for signature, and higher {non} nonce)".format(
			tot = (8 * (2**self.landlord_size_log)),
			sig = self.signature_size_in_bits,
			non = (8 * (2**self.landlord_size_log)) - self.signature_size_in_bits))
		strlist.append("Landlords per cache line: {}".format(2**self.landlord_cache_line_capacity_log))
		return "\n".join(strlist)

	def _getLandlordLayerSize(self, layerIndex:int, domain_log:typing.Optional[int]=None) -> int:
		"""Returns the i-th landlord layer's memory footprint.
		"""
		if domain_log is None:
			domain_log = self.domain_log
		for i in range(layerIndex+1):
			assert(domain_log >= self.program_cache_line_size_log)
			domain_log -= self.program_cache_line_size_log if (i == 0) \
				else self.landlord_cache_line_size_log
			domain_log += self.landlord_size_log
		return (2**domain_log)
	
	def _calcTreeSize(self, alpha_ll_size_log:typing.Optional[int]=None, *, include_root_layer:bool=True) -> int:
		"""Tree size is greater than alpha_ll_size
		"""
		root_layer_subtraction = 0 if include_root_layer else 1
		totalSize = 0
		for l in range(self._calcLandlordLayersCount(None, alpha_ll_size_log) - root_layer_subtraction):
			totalSize += self._getLandlordLayerSize(l)
			logging.debug("Layer #{} size: {}B".format(l, self._getLandlordLayerSize(l)))
		return totalSize

	def _calcLandlordLayersCount(self, domain_log=None, alpha_ll_size_log=None) -> int:
		"""Returns the depth of the tree graph. (Depth >= 1)
		"""
		if domain_log is None:
			domain_log = self.domain_log
		if alpha_ll_size_log is None:
			alpha_ll_size_log = self.alpha_ll_size_log
		
		layersCount = 0
		ll_leaves = self._getLandlordLayerSize(layersCount, domain_log)
		while ll_leaves > 2**alpha_ll_size_log:
			layersCount += 1
			ll_leaves = self._getLandlordLayerSize(layersCount, domain_log)
		return layersCount + 1

	def getAddressFromLandlordAddress(self, addr:int):
		"""Reversed form of :py:func:`getLandlordIndex()`
		addr - the landlord address.
		Returns the lowest address of the corresponding resident
		of the given landlord.
		"""
		if not self.isValidLandlordAddress(addr):
			raise ValueError
		elif not self._isCachelineAligned(addr):
			raise ValueError("@addr must be lowest address of a landlord")
		# addr &= -(2**self.landlord_cache_line_size_log) # cache align
		addr -= self.landlord_base_ptr

		for layerIndex in range(self._calcLandlordLayersCount()):
			layerSize = self._getLandlordLayerSize(layerIndex)
			if (addr >= layerSize):
				addr -= layerSize
				continue	

			addr >>= self.landlord_size_log
			if layerIndex == 0:
				# lowest layer
				addr <<= self.program_cache_line_size_log
				if addr >= self.landlord_base_ptr:
					addr += self.tree_size
			else:
				addr <<= self.landlord_cache_line_size_log
				for i in range(layerIndex-1):
					addr += self._getLandlordLayerSize(i)
				addr += self.landlord_base_ptr
			return addr
		raise AssertionError
		
	def _getLandlordIndexAux(self, abs_ll_index:int) -> LandlordCoorType:
		assert((abs_ll_index << self.landlord_size_log) < self.tree_size)
		indx = abs_ll_index # assign the source landlord index to destination landlord index
		relative_address, layer = 0,0
		for layer in range(self.landlordLayersCount - 1):
			layer_size = self._getLandlordLayerSize(layer)
			#logging.debug("layer size is: {}".format(layer_size))
			relative_address += layer_size
			if ((indx << self.landlord_size_log) < layer_size) or (layer_size == 0):
				break
			# elif (layer_size <= 2**self.alpha_ll_size_log):
			# 	raise ValueError("alpha landlord does not comply to anyone but itself")
			indx -= (layer_size >> self.landlord_size_log)
		indx >>= self.landlord_cache_line_capacity_log # next layer's index
		ll_address = (self.landlord_base_ptr + relative_address + (indx << self.landlord_size_log)) # landlord virtual address
		bindx = (ll_address - self.landlord_base_ptr) >> self.landlord_size_log
		return LandlordConverter.LandlordCoordinates( bindx, layer+1, indx, ll_address )
			
	def getLandlordIndex(self, addr:int) -> LandlordCoorType:
		"""Returns a tuple: <Index, ABS(Index), Layer, Landlord_address>
		"""
		if not self.isValidAddress(addr):
			raise LandlordConverter.InvalidAddressError()
		if self.isValidLandlordAddress(addr):
			return self._getLandlordIndexAux((addr - self.landlord_base_ptr) >> self.landlord_size_log)
		logging.debug("address {} is not landlord".format(hex(addr)))
		relative_address = self._dataCachelineAlign(addr)
		if (addr >= self.landlord_base_ptr):
			relative_address -= self.tree_size
		indx = relative_address >> self.program_cache_line_size_log
		return LandlordConverter.LandlordCoordinates( indx , 0 , indx, (self.landlord_base_ptr + (indx << self.landlord_size_log)) )

	def getLandlordBranch(self, addr:int, len:int=1):
		"""Return a generator.
		"""
		layer = (-1)
		while (layer < self.landlordLayersCount - 1):
			co = self.getLandlordIndex(co.address if (layer >= 0) else addr)
			layer = co.layer_number # positive integer
			yield co

	def getRandomAddress(self, *, notLandlord:bool=True):
		"""Chooses a random valid address, using the python
		library's :py:func:`random.randrange`.
		"""
		def rrange(stop):
			from random import randrange
			return randrange(0, stop)
		addr = 0 # init
		if notLandlord:
			addr = rrange(2**(self.domain_log)-self.tree_size)
			if (addr >= self.landlord_base_ptr):
				addr += self.tree_size # normalize
			assert(self.isValidDataAddress(addr))
		else:
			addr = rrange(2**self.domain_log)
		return addr

	def debug_getLandlordIndex(self, source_address:int, sourceLength:int=1, *,
		traverseUp:bool=True, constantFormat:bool=False) -> str:
		from math import ceil
		assert (sourceLength >= 1)
		end_address = source_address + sourceLength - 1
		co_start = self.getLandlordIndex(source_address)
		sourceAddressIsLandlord = co_start.layer_number > 0
		sourceCachelineSize = 2 ** (
			self.landlord_cache_line_size_log if sourceAddressIsLandlord
			else self.program_cache_line_size_log)
		
		length = sourceLength
		if (source_address % sourceCachelineSize != 0):
			# source isn't cacheline aligned
			length += source_address % sourceCachelineSize
			co_start = self.getLandlordIndex(
				source_address - (source_address % sourceCachelineSize))

		#: Calculate the number of cachelines the source requires
		#: therefore, the number of different landlords required
		sourceCachelinesOccupancy = ceil(length / sourceCachelineSize)
		landlordLength = sourceCachelinesOccupancy * (2**self.landlord_size_log)

		#: build the report format, based on given variables and constantFormat keyword
		s_format = ["Source address: {s_address}"]
		if constantFormat or (end_address != source_address):
			s_format.append("-{e_address}")
		s_format.append(";\tLandlord address:{s_lladdr}")
		if constantFormat or (landlordLength > 1):
			s_format.append("-{e_lladdr}")
		s_format.append(" < ")
		s_format.append("{absindx} , ")
		s_format.append("{layerindx} , {relindx}")
		if constantFormat or (landlordLength > 1):
			s_format.append(" , {lllength}")
		s_format.append(" >")

		if not traverseUp:
			# Traverse before yield
			if (co_start.layer_number < self.landlordLayersCount - 1):
				yield from self.debug_getLandlordIndex(co_start.address, landlordLength)

		yield ''.join(s_format).format(
			s_address 	=	hex(source_address),
			e_address 	=	hex(end_address),
			s_lladdr 	=	hex(co_start.address),
			e_lladdr	=	hex(co_start.address + landlordLength - 1),
			absindx		=	relaxhex(co_start.segment_offset),
			layerindx	=	relaxhex(co_start.layer_number),
			relindx 	=	relaxhex(co_start.rel_index),
			lllength	=	sourceCachelinesOccupancy
		)

		if traverseUp:
			# Yield before traverse
			if (co_start.layer_number < self.landlordLayersCount - 1):
				yield from self.debug_getLandlordIndex(co_start.address, landlordLength)

	def __call__(self, addr:typing.Optional[int]=None, length:int=1):
		"""Currently calls :py:func:`debug_getLandlordIndex`()
		with the given address.
		When called without any arguments, defaults to random address
		using :py:func:`LandlordConverter.getRandomAddress`, and length=1.
		"""
		if (length < 1):
			raise TypeError("length must be positive")
		if addr is None:
			addr = self.getRandomAddress()
			print("The chosen address is: {}".format(relaxhex(addr)))
		for layer in self.debug_getLandlordIndex(addr, length):
			print(layer)

#end of class LandlordConverter


c30 = LandlordConverter(30, 2**6, 5, 1, 8, ll_base_ptr=0x20000000) # 32-bit address
c39 = LandlordConverter(39, 2**6, 6, 2, 16, ll_base_ptr=0x200000000) # 64-bit address

# sanity.py

import typing

from landlord import converter
from landlord import elfile
from tests import utils as test_utils

@test_utils.time_deco
def test1(filename, conver:converter.LLConvType,
	ignoreBlankLandlords:bool=True):
	"""Call :py:func:`Elfile.generateLandlords()` to
	calculate the file's landlords.
	"""
	with elfile.Elfile(filename) as fle:
		print(fle)
		# fle.readHeader()
		# fle.readSegmentTable()
		if not fle.isStaticallyLinkedExec():
			return
		with test_utils.tag():
			landlordsDict = fle.generateLandlords(conver,
				ignoreBlankLandlords=ignoreBlankLandlords)
			for k in sorted(list(landlordsDict)):
				print("{key:#X} : {val:#{width}X}\t(refers to: {srcaddr:#X})".format(
					key=k, val=landlordsDict[k],
					width = (conver.signature_size_in_bits // 4),
					srcaddr = conver.getAddressFromLandlordAddress(k)))

@test_utils.time_deco
def test2(filename, conver:converter.LLConvType):
	"""Call :py:func:`Elfile.encrypt`.
	"""
	with elfile.Elfile(filename) as fle:
		if fle.isStaticallyLinkedExec():
			print("Successfully cloned to: {}".format(fle.encrypt(conver)))

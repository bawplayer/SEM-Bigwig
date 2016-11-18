#!/usr/bin/env python3
#__author__ = "bawplayer"
# EXECUTE FROM THE TOP DIRECTORY

from landlord import elfile as elfi
from landlord import converter
import sys
import os.path
import logging

def time_deco(func):
	from functools import wraps
	@wraps(func)
	def td_wrapper(*args, **kwargs):
		from datetime import datetime
		start = datetime.now()
		res = func(*args, **kwargs)
		end = datetime.now()
		logging.info("Time delta is: {}".format(end-start))
		return res
	return td_wrapper

@time_deco
def test1(filename, conver, *, ignoreBlankLandlords=True):
	"""Call :py:func:`Elfile.generateLandlords()` to
	calculate the file's landlords.
	"""
	with elfi.Elfile(filename) as fle:
		print(fle)
		# fle.readHeader()
		# fle.readSegmentTable()
		if fle.isStaticallyLinkedExec():
			print("""----------------------------------------------""")
			landlordsDict = fle.generateLandlords(conver,
				ignoreBlankLandlords=ignoreBlankLandlords)
			for k in sorted(list(landlordsDict)):
				print("{key:#X} : {val:#{width}X}\t(refers to: {srcaddr:#X})".format(
					key=k, val=landlordsDict[k],
					width = (conver.signature_size_in_bits // 4),
					srcaddr = conver.getAddressFromLandlordAddress(k)))
		print("""----------------------------------------------""")

@time_deco
def test2(filename, conver):
	"""Call :py:func:`Elfile.encrypt`.
	"""
	with elfi.Elfile(filename) as fle:
		if fle.isStaticallyLinkedExec():
			print("Successfully cloned to: {}".format(fle.encrypt(conver)))

@time_deco
def dumpLandlordsToFile(srcfile, destfile, conver, overrideDestination=True,
	*, ignoreBlankLandlords=True):
	"""Dump the landlords addresses and values using JSON.
	By default, overrides destfile when exists.
	"""
	import json
	if (not overrideDestination) and os.path.exists(destfile):
		raise FileExistsError("destination file already exitsts")
	with elfi.Elfile(srcfile) as fle:
		if not fle.isStaticallyLinkedExec():
			raise ValueError("Source file is not statically linked executable")
		landlordsDict = fle.generateLandlords(conver,
				ignoreBlankLandlords=ignoreBlankLandlords)
		with open(destfile, 'w') as dest:
			json.dump(landlordsDict, dest, sort_keys=True, indent=3)

def main(*filenames, conver=converter.c30):
	form = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(levelname)s:%(message)s";\
	logging.basicConfig(format=form, level=logging.DEBUG)
	logging.debug(str(conver))
	
	if not filenames:
		fname = os.path.join("tst", "tiny.out")
		if os.path.exists(fname):
			filenames = [fname,]

	for arg in filenames:
		if not os.path.isfile(arg):
			print("Test file {} is not found".format(arg), file=sys.stderr)
			continue
		test1(arg, conver)
		test2(arg, conver)


if __name__ == "__main__":
	main(*sys.argv[1:])

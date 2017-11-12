#!/usr/bin/env python3
# __author__ = "bawplayer"
# EXECUTE FROM THE TOP DIRECTORY

import contextlib
import functools
import json
import logging
import os.path
import sys
import typing

from landlord import command_parser
from landlord import converter
from landlord import elfile
from tests import utils as test_utils
from tests import sanity as test_sanity

# 32-bit address landlord converter example
conv30 = converter.LandlordConverter(
	domain_log=30,
	alpha_ll_max_size_in_bytes=2**6,
	cache_line_size_log=5,
	landlord_size_log=1,
	signature_size_in_bits=8,
	landlord_base_ptr=0x20000000)

# 64-bit address landlord converter example
conv39 = converter.LandlordConverter(
	domain_log=39,
	alpha_ll_max_size_in_bytes=2**6,
	cache_line_size_log=6,
	landlord_size_log=2,
	signature_size_in_bits=16,
	landlord_base_ptr=0x200000000)

@test_utils.time_deco
def dumpLandlordsToFile(srcfile, destfile, conver:converter.LLConvType,
	overrideDestination:bool=True, ignoreBlankLandlords:bool=True):
	"""Dump the landlords addresses and values using JSON.
	By default, overrides destfile when exists.
	"""
	if (not overrideDestination) and os.path.exists(destfile):
		raise FileExistsError("destination file already exitsts")
	with elfile.Elfile(srcfile) as fle:
		if not fle.isStaticallyLinkedExec():
			raise ValueError("Source file is not statically linked executable")
		landlordsDict = fle.generateLandlords(conver,
				ignoreBlankLandlords=ignoreBlankLandlords)
		with open(destfile, 'w') as dest:
			json.dump(landlordsDict, dest, sort_keys=True, indent=3)


def call_tests(*filenames, conver=conv30):
	if not filenames:
		fname = os.path.join("tst", "tiny.out")
		if os.path.exists(fname):
			filenames = [fname,]

	if not filenames:
		print("Nothing to do", file=sys.stderr)
		return

	for fn in filenames:
		if not os.path.isfile(fn):
			print("File {} is not found".format(fn), file=sys.stderr)
			continue
		i = 0
		while True:
			i += 1  # 1st index equals 1
			try:
				getattr(test_sanity, "test%d" % i)(fn, conver)
			except AttributeError:
				break

def main():
	form = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(levelname)s:%(message)s"
	logging.basicConfig(format=form, level=logging.DEBUG)

	args = command_parser.get_parser().parse_args()
	curr_converter = converter.LandlordConverter(
		domain_log=args.address_width,
		alpha_ll_max_size_in_bytes=args.alpha_size,
		cache_line_size_log=converter.clog2(args.cache_line_size),
		landlord_size_log=converter.clog2(args.landlord_size),
		signature_size_in_bits=args.signature_size,
		landlord_base_ptr=args.landlord_base_address,
		)
	logging.info(str(curr_converter))
	call_tests(*args.filenames, conver=curr_converter)

if __name__ == "__main__":
	main()

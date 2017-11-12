# command_parser.py

import argparse

from landlord import constants

def generic_int(x):
	return int(x, 0)

def get_parser():
	parser = argparse.ArgumentParser(
		description="Test landlord graph",
		formatter_class=argparse.ArgumentDefaultsHelpFormatter,
		)
	parser.add_argument(constants.FILENAMES_ARGUMENT, metavar="FILENAME", type=str, nargs='*')
	parser.add_argument("--" + constants.ADDRESS_WIDTH, metavar="<#bits>", type=generic_int,
		default=constants.ADDRESS_WIDTH_DEFAULT_VAL,
		help="Address width specified in bits, default to 32-bit system")
	parser.add_argument("--" + constants.CACHELINE_SIZE, metavar="<#bytes>", type=generic_int,
		default=constants.CACHELINE_SIZE_DEFAULT_VAL,
		help="Set cacheline size in bytes")
	parser.add_argument("--" + constants.ALPHA_SIZE, metavar="<#bytes>", type=generic_int,
		default=constants.ALPHA_SIZE_DEFAULT_VAL,
		help="alpha landlord block max size specified in number of bytes")
	parser.add_argument("--" + constants.LANDLORD_SIZE, metavar="<#bytes>", type=generic_int,
		default=constants.LANDLORD_SIZE_DEFAULT_VAL,
		help="Set landlord size in bytes. (both nonce and signature)")
	parser.add_argument("--" + constants.SIGNATURE_SIZE, metavar="<#bits>", type=generic_int,
		default=constants.SIGNATURE_SIZE_DEFAULT_VAL,
		help="Set landlord's signature size")
	parser.add_argument("--" + constants.LANDLORD_BASE_ADDR, metavar="<address>",
		type=generic_int, default=constants.LANDLORD_BASE_ADDR_DEFAULT_VAL,
		help="Set base memory address for the landlords block")
	return parser

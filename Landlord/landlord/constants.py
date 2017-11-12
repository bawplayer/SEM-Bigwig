
# Parser arguments
FILENAMES_ARGUMENT = "filenames"
ADDRESS_WIDTH = '-'.join(["address", "width"])
CACHELINE_SIZE = '-'.join(["cache", "line", "size"])
ALPHA_SIZE = '-'.join(["alpha", "size"])
LANDLORD_SIZE = '-'.join(["landlord", "size"])
SIGNATURE_SIZE = '-'.join(["signature", "size"])
LANDLORD_BASE_ADDR = '-'.join(["landlord", "base", "address"])

# DEFAULT ARGUMENTS
ADDRESS_WIDTH_DEFAULT_VAL = 30  # bits
CACHELINE_SIZE_DEFAULT_VAL = 2**5  # bytes
ALPHA_SIZE_DEFAULT_VAL = 2**6  # bytes
LANDLORD_SIZE_DEFAULT_VAL = 2  # bytes
SIGNATURE_SIZE_DEFAULT_VAL = 8  # bits
LANDLORD_BASE_ADDR_DEFAULT_VAL = "0x20000000"

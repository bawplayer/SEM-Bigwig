#Python C API
from distutils.core import setup, Extension
import os
import logging

module_name = "elfexmod"
modules_dir = "lib"
dest_dir = "."

#logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

module1 = Extension(module_name,
	#define_macros = [('MAJOR_VERSION', '1'), ('MINOR_VERSION', '0')],
	include_dirs = [modules_dir],
	#libraries = ["pthread"],
	extra_compile_args = ["-std=c11"],
	extra_link_args = ["-Wl,-wrap,malloc -Wl,-wrap,realloc -Wl,-wrap,free"],
	sources = [os.path.join(modules_dir, mod) for mod in ["elfexmodule.c", "elfutil.c", "semutil.c", "mmaputil.c", "malloc_wrapper.c"]]
)

setup(name = "ELFModule",
	version = "1.0.0",
	description = "ELF file Python extension module",
	author = "BARKer",
	ext_modules = [module1])


try:
	#find the (compiled) shared library
	assert("build" in os.listdir())
	libl = [x for x in os.listdir("build") if x.startswith("lib")]
	exel = [x for x in os.listdir(os.path.join("build", libl[0]))
		if x.startswith(module_name) and x.endswith(".so")]
	exepath = os.path.join("build", libl[0], exel[0])
	linkpath = os.path.join(dest_dir, module_name + ".so")
	assert(os.path.exists(exepath))

	#create symlink to elfexmod.so
	if os.path.lexists(linkpath):
		os.unlink(linkpath)
	assert(not os.path.exists(linkpath))
	#os.rmdir("build")
except:
	raise ImportError
os.link(exepath, linkpath)
from contextlib import contextmanager
import functools
import logging
import typing

@contextmanager
def tag(len:int=50):
	_tag = "-"*len
	print(_tag)
	yield
	print(_tag)

def time_deco(func):
	@functools.wraps(func)
	def td_wrapper(*args, **kwargs):
		from datetime import datetime
		print("Enters test {}".format(func.__name__))
		start = datetime.now()
		res = func(*args, **kwargs)
		end = datetime.now()
		logging.info("Time delta is: {}".format(end-start))
		print("Exits test {}".format(func.__name__))
		return res
	return td_wrapper

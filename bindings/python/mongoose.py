#  Copyright (c) 2004-2009 Sergey Lyubka
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#  THE SOFTWARE.
#
#  $Id$

"""
This module provides python binding for the Mongoose web server.

There are two classes defined:

  Connection: - wraps all functions that accept struct mg_connection pointer
    as first argument

  Mongoose: wraps all functions that accept struct mg_context pointer as
    first argument. All valid option names, settable via mg_set_option(),
    are settable/gettable as the attributes of the Mongoose object.
    In addition to those, two attributes are available:
       'version': string, contains server version
       'options': array of all known options.

  Creating Mongoose object automatically starts server, deleting object
  automatically stops it. There is no need to call mg_start() or mg_stop().
"""

import ctypes
import os


class mg_header(ctypes.Structure):
	"""A wrapper for struct mg_header."""
	_fields_ = [
		('name', ctypes.c_char_p),
		('value', ctypes.c_char_p),
	]


class mg_request_info(ctypes.Structure):
	"""A wrapper for struct mg_request_info."""
	_fields_ = [
		('request_method', ctypes.c_char_p),
		('uri', ctypes.c_char_p),
		('query_string', ctypes.c_char_p),
		('post_data', ctypes.c_char_p),
		('remote_user', ctypes.c_char_p),
		('remote_ip', ctypes.c_long),
		('remote_port', ctypes.c_int),
		('post_data_len', ctypes.c_int),
		('http_version_major', ctypes.c_int),
		('http_version_minor', ctypes.c_int),
		('status_code', ctypes.c_int),
		('num_headers', ctypes.c_int),
		('http_headers', mg_header * 64),
	]


class mg_option(ctypes.Structure):
	"""A wrapper for struct mg_option."""
	_fields_ = [
		('name', ctypes.c_char_p),
		('description', ctypes.c_char_p),
		('default_value', ctypes.c_char_p),
	]


class Connection(object):
	"""A wrapper class for all functions that take
	struct mg_connection * as the first argument."""

	def __init__(self, mongoose, connection):
		self.m = mongoose
		self.conn = connection

	def get_header(self, name):
		val = self.m.dll.mg_get_header(self.conn, name)
		return ctypes.c_char_p(val).value

	def get_var(self, name):
		var = None
		pointer = self.m.dll.mg_get_var(self.conn, name)
		if pointer:
			var = ctypes.c_char_p(pointer).value
			self.m.dll.mg_free_var(pointer)
		return var

	def printf(self, fmt, *args):
		val = self.m.dll.mg_printf(self.conn, fmt, *args)
		return ctypes.c_int(val).value

	def write(self, data):
		val = self.m.dll.mg_write(self.conn, data, len(data))
		return ctypes.c_int(val).value


class Mongoose(object):
	"""A wrapper class for Mongoose shared library."""

	# Exceptions for __setattr__ and __getattr__: these attributes
	# must not be treated as Mongoose options
	_private = ('dll', 'ctx')

	def __init__(self, **kwargs):
		dll_extension = os.name == 'nt' and 'dll' or 'so'
		self.dll = ctypes.CDLL('_mongoose.%s' % dll_extension)
		start = self.dll.mg_start
		self.ctx = ctypes.c_voidp(self.dll.mg_start()).value
		for name, value in kwargs.iteritems():
			self.__setattr__(name, value)

	def __setattr__(self, name, value):
		"""Set Mongoose option. Raises ValueError in option not set."""
		if name in self._private:
			object.__setattr__(self, name, value)
		else:
			code = self.dll.mg_set_option(self.ctx, name, value)
			if code != 1:
				raise ValueError('Cannot set option [%s] '
						 'to [%s]' % (name, value))

	def __getattr__(self, name):
		"""Get Mongoose option."""
		if name in self._private:
			return object.__getattr__(self, name)
		elif name == 'version':
			val = self.dll.mg_version()
			return ctypes.c_char_p(val).value
		elif name == 'options':
			func = self.dll.mg_get_option_list
			func.restype = ctypes.POINTER(mg_option)
			return func()
		else:
			val = self.dll.mg_get_option(self.ctx, name)
			return ctypes.c_char_p(val).value

	def __del__(self):
		"""Destructor, stop Mongoose instance."""
		self.dll.mg_stop(self.ctx)

	def _bind(self, what, callback, data, func_name):
		"""Register URI, error or auth callback."""

		# Create a closure that will be called by the  shared library.
		def _cb(connection, request_info, data):
			# Wrap connection pointer into the connection
			# object and call user specified function.
			conn = Connection(self, connection)
			callback(conn, request_info.contents, data)

		cb = ctypes.CFUNCTYPE(ctypes.c_voidp, ctypes.c_voidp,
			ctypes.POINTER(mg_request_info), ctypes.c_voidp)(_cb)

		self.dll[func_name](self.ctx, what, cb, data)

	def bind_to_uri(self, uri_regex, callback, data):
		self._bind(uri_regex, callback, data, 'mg_bind_to_uri')

	def bind_protect_uri(self, uri_regex, callback, data):
		self._bind(uri_regex, callback, data, 'mg_protect_uri')

	def bind_to_error_code(self, error_code, callback, data):
		self._bind(error_code, callback, data, 'mg_bind_to_error_code')

# qbic-pwresetd a password reset daemon for the QBiC services
# Copyright (C) 2016  Sven Nahnsen <sven.nahnsen@uni-tuebingen.de>

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

# --------------------------------------------------------------------------
# $Author: Enrico Tagliavini <enrico.tagliavini@uni-tuebingen.de> $
# $Author: Erhan Kenar <erhan.kenar@uni-tuebingen.de> $
# --------------------------------------------------------------------------

__author__ = 'Enrico Tagliavini <enrico.tagliavini@uni-tuebingen.de>, Erhan Kenar <erhan.kenar@uni-tuebingen.de>'

import MySQLdb
import sqlite3
import struct
import sys

from . import config
from datetime import datetime, timedelta
from pytz import utc
from calendar import timegm
from traceback import format_exc

datetime_format = '%Y-%m-%d %H:%M:%S'
rr_t = struct.Struct('<I?Q')
class ResetRequest:
	def __init__(self, *args, **kwargs):
		if len(args) == 1 and len(kwargs) == 0:
			self.__init_from_pack__(args[0])
			return
		else:
			self.__init_from_params__(*args, **kwargs)
			return
		raise TypeError('Wrong __init__ parameters')

	def __init_from_params__(self, account_name = '', secret_code = '', duration = 48, active = False, creation_timestamp = None):
		if account_name is '' or secret_code is '':
			raise TypeError('Must specify both account_name and secret_code not empty')
		self.account_name = account_name
		self.secret_code = secret_code
		self.duration = duration
		self.active = active
		if creation_timestamp is None:
			self.creation_timestamp = datetime.utcnow()
		elif type(creation_timestamp) == datetime:
			self.creation_timestamp = creation_timestamp
		else:
			raise TypeError('creation_timestamp must be of type datetime.datetime, but got type %s' % type(creation_timestamp).__name__)
		return

	def __init_from_pack__(self, pdata):
		(self.duration, self.active, unix_time) = rr_t.unpack(pdata[len(pdata) - rr_t.size:])
		(self.account_name, self.secret_code) = pdata[:len(pdata) - rr_t.size].split('\0', 2)
		self.creation_timestamp = datetime.utcfromtimestamp(unix_time)
		return

	def __str__(self):
		return (self.account_name + '\t' + self.secret_code + '\t' +
			  self.creation_timestamp.strftime(datetime_format) + '\t' + str(self.duration) + '\t' + str(self.active)
		)

	def expired(self):
		ed = self.expiry_date()
		now = datetime.utcnow()
		if (ed - now).total_seconds() > 0:
			return False
		return True

	def expiry_date(self, tz = None):
		ret = self.creation_timestamp + timedelta(hours = self.duration)
		if tz is not None:
			# first turn a naive datetime to a tz aware one
			# we store everything UTC so set it
			ret = ret.replace(tzinfo=utc).astimezone(tz)
		return ret

	def pack(self):
		ret = '\0'.join([self.account_name, self.secret_code]) + \
				rr_t.pack(
					self.duration,
					self.active,
					timegm(self.creation_timestamp.utctimetuple())
				)
		return ret

class DBManager:
	def __init__(self, engine, uri, **kwargs):
		self.db_connection = None
		self.db_cursor = None
		try:
			
			if engine == 'mysql':
				self.db_module = MySQLdb
				self._placeholder = r'%s'
				self.uri = uri
				self.rrequests_table = kwargs['rrequests_table']
				self.username = kwargs['username']
				self.password = kwargs['password']
				self.database = kwargs['database']
				if 'unix_socket' in kwargs:
					self.unix_socket = kwargs['unix_socket']
			elif engine == 'sqlite':
				self.db_module = sqlite3
				self._placeholder = r'?'
				self.uri = uri
				self.rrequests_table = kwargs['rrequests_table']
			else:
				raise ValueError('Database module `%s\' not suported' % engine)
		except KeyError as e:
			raise ValueError('Missing keyword argument \'%s\' for database module %s' % (e.message, engine))

	def add_request(self, reset_request):
		account_name = reset_request.account_name
		secret_code = reset_request.secret_code
		creation_timestamp = reset_request.creation_timestamp
		reset_duration = reset_request.duration
		active = reset_request.active
		insert_cmd = r'INSERT INTO {table} '.format(table = self.rrequests_table) + \
			'(account_name, secret_code, creation_timestamp, reset_duration, is_active) ' + \
			'VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})'.format(
				placeholder = self._placeholder
			)
		self.db_cursor.execute(
				insert_cmd,
				(account_name, secret_code, creation_timestamp.strftime(datetime_format), reset_duration, active)
		)
		if config.testonly:
			self.db_connection.rollback()
		else:
			self.db_connection.commit()
		return

	def connect(self):
		if self.db_connection is not None:
			# we are already connected!
			# FIXME? raise an error instead? Not sure here. If we ask the object to connect
			# and it is already connected at the end of the day we have what we want
			# for now let's just log a warning, just to see if it happens
			sys.stderr.write('WARNING: DBManager: called connect but db is already connected\n%s\n' % format_exc(), WARNING)
			return
		if self.db_module.__name__ == 'MySQLdb':
			# UNIX socket should be used by default for local connections
			# don't set or check it, default should work
			# workaround for MySQLdb but not accepting unix_socket with value None (MySQL C API accepts NULL)
			if self.unix_socket is not None:
				self.db_connection = self.db_module.connect(host = self.uri, user = self.username, passwd = self.password,
						db = self.database, use_unicode = True, unix_socket = self.unix_socket, charset = 'utf8')
			else:
				self.db_connection = self.db_module.connect(host = self.uri, user = self.username, passwd = self.password,
						db = self.database, use_unicode = True, charset = 'utf8')
		elif self.db_module.__name__ == 'sqlite3':
			self.db_connection = self.db_module.connect(self.uri)
			self.db_connection.text_factory = str

		self.db_cursor = self.db_connection.cursor()
		if self.db_module.__name__ == 'sqlite3':
			# self initialize the DB
			try:
				self.db_cursor.execute(r'CREATE TABLE %s(request_id INTEGER PRIMARY KEY AUTOINCREMENT, account_name TEXT NOT NULL, secret_code TEXT UNIQUE NOT NULL, creation_timestamp TEXT NOT NULL, reset_duration INT NOT NULL, is_active INT NOT NULL)' % self.rrequests_table)
			except sqlite3.OperationalError as e:
				pass
		return

	def disconnect(self):
		if self.db_cursor is not None:
			self.db_cursor.close()
			self.db_cursor = None
		if self.db_connection is not None:
			self.db_connection.close()
			self.db_connection = None
		return

	def get_request(self, secret):
		fetch_results = []
		select_cmd = r'SELECT * FROM {table} WHERE secret_code = {placeholder}'.format(
				table = self.rrequests_table,
				placeholder = self._placeholder
		)
		self.db_cursor.execute(select_cmd, (secret,))
		fetch_results = self.db_cursor.fetchone()
		if fetch_results is None:
			return None
		#fetch_results = self.db_cursor.fetchmany(10)
		# TODO return a ResetRequest object instead this class should abstract the DB
		# not just dumping it to the caller
		(r_id, username, secret, ctime, duration, active) = fetch_results
		if self.db_module.__name__ == 'sqlite3':
			ctime = datetime.strptime(ctime, datetime_format)
			active = bool(active)
		return ResetRequest(
				account_name = username,
				secret_code = secret,
				duration = duration,
				active = active,
				creation_timestamp = ctime
		)

	def list_requests(self, limit=50):
		fetch_results = []
		self.db_cursor.execute(r'SELECT * FROM ' + self.rrequests_table)
		fetch_results = self.db_cursor.fetchmany(limit)
		ret = []
		for (r_id, username, secret, ctime, duration, active)  in fetch_results:
			if self.db_module.__name__ == 'sqlite3':
				ctime = datetime.strptime(ctime, datetime_format)
				active = bool(active)
			ret.append(ResetRequest(
					account_name = username,
					secret_code = secret,
					duration = duration,
					active = active,
					creation_timestamp = ctime
			))
		return ret

	def update_request_by_secret(self, secret_code, field_name, field_value):
		update_cmd = r'UPDATE {table} SET {field} = {placeholder} WHERE secret_code = {placeholder}'.format(
				table = self.rrequests_table,
				field = field_name,
				placeholder = self._placeholder
		)
		if self.db_module == MySQLdb:
			self.db_cursor.execute(r'LOCK TABLES {table} WRITE'.format(table = self.rrequests_table))
		self.db_cursor.execute(update_cmd, (field_value, secret_code))
		ret = self.db_cursor.rowcount
		if ret == 0:
			# check if the value was already as specified
			req = self.get_request(secret_code)
			if req is not None:
				# one request with the same secret was found
				# assume the line was not changed since the new value is
				# the same as the old one
				ret = 1
		if config.testonly:
			self.db_connection.rollback()
		else:
			self.db_connection.commit()
		if self.db_module == MySQLdb:
			# looks like it will commit in the moment we unlock the tables, so do it now
			self.db_cursor.execute(r'UNLOCK TABLES')
		return ret


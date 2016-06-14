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
# --------------------------------------------------------------------------

__author__ = 'Enrico Tagliavini <enrico.tagliavini@uni-tuebingen.de>'

import re
import struct

from . import readpackets, sendpackets, ProtocolError, BadRequest, a_ack, a_nak, a_badrequest, a_error
from . import crta_t, unpack_uint, uint_t
from base64 import standard_b64encode, standard_b64decode


secret_sanitize_re = re.compile(r'[^\w.,-_]')

def _parse_create_request(args):
	# args == 'username=qbicqbc01 secret|autogenerate crta_t.pack(hours, enabled)'
	# args == 'email=standard_b64encode('user@example.com') secret|autogenerate crta_t.pack(hours, enabled)'

	# first argument: username=|email=
	if args[0].startswith('username='):
		username = args[0].split('=')[1]  # len will be 2 since there is a '=' char in the string
		if len(username) <= 0:
			raise BadRequest('no username specified')
		first = args[0]
	elif args[0].startswith('email='):
		try:
			email = standard_b64decode(args[0].split('=', 1)[1])
		except TypeError:
			raise BadRequest('cannot decode email address in: %s' % repr(args[0]))
		first = 'email=' + email
	else:
		raise BadRequest('first argument must start with username=|email=')	

	# second argument: secret
	secret = args[1]
	if secret != 'autogenerate':
		# IMPORTANT check the secret to contain only digits, letters and some punctuation. Nothing else is permitted
		m = secret_sanitize_re.search(secret)
		if m is not None:
			raise BadRequest('found forbidden character(s) in secret: %s' % repr(secret[m.start():m.end()]))

	# third argument: crta_t.pack(hours, enabled)
	try:
		(duration, enabled) = crta_t.unpack(args[2])
	except struct.error as e:
		raise BadRequest('cannot unpack C struct in third argument: ' + args[2])
	
	return [first, secret, duration, enabled]

def _parse_list_requests(args):
	try:
		limit = unpack_uint(args[0])
	except struct.error as e:
		raise BadRequest('cannot unpack int struct in first argument: ' + args[0])
	return [limit]

def _parse_reset_password(args):
	username = args[0]
	secret = args[1]
	try:
		new_password = standard_b64decode(args[2])
	except TypeError:
		raise BadRequest('cannot decode new password: %s' % repr(args[2]))
	return [username, secret, new_password]

def _parse_enable_request(args):
	return args

#def _parse_send_email(args):
#	ret = []
#	for pair in args:
#		try:
#			(sec, msg_type) = pair.rsplit('\0', 1)
#			msg_type = msg_type.lower()
#		except ValueError:
#			sec = pair
#			msg_type = 'default_reset'
#		ret.append((sec, msg_type))
#	return [ret]

def _parse_send_email(args):
	ret = []
	if len(args) < 2:
		raise BadRequest('SENDEMAIL: requires at least 2 arguments, %d given' % len(args))
	return [args[0].lower(), args[1:]]

_cmd2parse_funct = {
	'CREATEREQUEST': (_parse_create_request, 3),
#	'GETREQUEST': (_parse_get_request, 1),  # Not implemented yet
	'LISTREQUESTS': (_parse_list_requests, 1),
	'RESETPW': (_parse_reset_password, 3),
	'ENABLEREQUEST': (_parse_enable_request, 1),
	'DISABLEREQUEST': (_parse_enable_request, 1),
	'SENDEMAIL': (_parse_send_email, '?'),
}
cmd_list = _cmd2parse_funct.keys() + ['TESTPROTOCOL','KTHXBYE']

def get_command(conn):
	line = readpackets(conn)
	if line is None:
		return (None, None)
	try:
		(cmd, args) = line.split(' ', 1)
		#args = args.split(' ')
	except ValueError:
		cmd = line.strip()
		args = None
	# set a default answer
	ret = args
	if args != None and cmd in _cmd2parse_funct:
		argv = args.split(' ')
		if _cmd2parse_funct[cmd][1] != '?' and len(argv) != _cmd2parse_funct[cmd][1]:
			raise BadRequest('%s: requires exactly 3 arguments, %d given' % (
				cmd, len(argv)
			))
		try:
			ret = _cmd2parse_funct[cmd][0](argv)
		# for now there are no ProtocolError raised here, but there may be in the future
		except ProtocolError as e:
			# being a bit lazy here to avoid passing cmd as a parameter
			raise ProtocolError('%s: %s' % (cmd, e.message), e.errors)
		except BadRequest as e:
			raise BadRequest('%s: %s' % (cmd, e.message))
	elif cmd in cmd_list:
		return (cmd, [args])
	elif args == None and cmd in _cmd2parse_funct:
		raise ProtocolError('got command %s without an argument' % cmd)
	elif cmd == '':
		return (None, None)
	else:
		raise ProtocolError('Unknown command %s' % cmd)
	return (cmd, ret)

def _simple_answer(status, data):
	if status is None:
		return data
	return '%s %s' % (status, data)

def _answer_list_requests(status, data):
	answer = status + ' '
	index = []
	raw_data = ''
	for r in data:
		raw_data += r.pack()
		index.append(len(raw_data))
	answer += uint_t.pack(len(index)) + ''.join(uint_t.pack(x) for x in index) + raw_data
	return answer

def _answer_enable_request(status, data):
	(secret, enabled) = data
	return '%s %s\0%s' % (status, secret, str(enabled))

def _answer_send_email(status, data):
	(ok, notok) = data
	if len(ok) == 0:
		status = a_nak
	else:
		status = a_ack
	return '%s %s\0%s' % (status, ' '.join(ok), ' '.join(notok))

_cmd2answer = {
	'CREATEREQUEST': (_simple_answer, []),
#	'GETREQUEST': (_answer_get_request, []),  # Not implemented yet
	'LISTREQUESTS': (_answer_list_requests, [a_ack]),
	'RESETPW': (_simple_answer, []),
	'ENABLEREQUEST': (_answer_enable_request, [a_ack]),
	'DISABLEREQUEST': (_answer_enable_request, [a_ack]),
	'SENDEMAIL': (_answer_send_email, [a_ack, a_nak]),
	'TESTPROTOCOL': (_simple_answer, []),
}
def send_answer(conn, status, answer, cmd = None):
	if cmd is None:
		sendpackets(conn, _simple_answer(status, answer))
		return
	if cmd not in cmd_list:
		raise ValueError('Unknown command %s' % cmd)
	if status not in _cmd2answer[cmd][1]:
		a_fnct = _simple_answer
	else:
		a_fnct = _cmd2answer[cmd][0]
	sendpackets(conn, a_fnct(status, answer))
	return


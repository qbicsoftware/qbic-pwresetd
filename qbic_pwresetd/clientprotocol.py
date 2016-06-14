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

import struct

from . import readpackets, sendpackets, BadAnswer, a_ack, a_nak, a_badrequest, a_error, answer_list
from . import crta_t, unpack_uint, uint_t
from .resetrequest import ResetRequest
from base64 import standard_b64encode, standard_b64decode


def _send_create_request(useroremail, secret, duration, enabled):
	return '%s %s %s' % (useroremail, secret, crta_t.pack(duration, enabled))

def _send_list_requests(limit):
	return uint_t.pack(limit)

def _send_reset_password(username, secret, new_password):
	return '%s %s %s' % (username, secret, standard_b64encode(new_password))

def _send_enable_request(secret):
	return secret

def _send_send_email(msg_type, secrets):
#	ret = []
#	for (secret, msg_type) in args:
#		if msg_type is not None:
#			ret.append('%s\0%s' % (secret, msg_type.upper()))
#		else:
#			ret.append(secret)
	return ' '.join([msg_type.upper()] + secrets)

_cmd2send = {
	'CREATEREQUEST': (_send_create_request, 4),
#	'GETREQUEST': (_send_get_request, 1),  # Not implemented yet
	'LISTREQUESTS': (_send_list_requests, 1),
	'RESETPW': (_send_reset_password, 3),
	'ENABLEREQUEST': (_send_enable_request, 1),
	'DISABLEREQUEST': (_send_enable_request, 1),
	'SENDEMAIL': (_send_send_email, '?'),
}
def send_request(conn, cmd, args):
	if cmd not in _cmd2send:
		req = ' '.join(args)
	else:
		if _cmd2send[cmd][1] != '?' and len(args) != _cmd2send[cmd][1]:
			raise TypeError('%s requires exactly %d arguments, %d given' % (cmd, _cmd2send[cmd][1], len(args)))
		req = _cmd2send[cmd][0](*args)
	sendpackets(conn, '%s %s' % (cmd, req))
	return


def _getint(buf, pos):
	try:
		return unpack_uint(buf[pos * uint_t.size : (pos + 1) * uint_t.size])
	except strict.error:
		raise BadAnswer('Invalid integer at position %d' % pos)

def _parse_simple_answer(args):
	return args

def _parse_answer_list_requests(args):
	n = _getint(args, 0)
	data = args[(n + 1) * uint_t.size:]
	p_pos = 0
	ret = []
	for i in range(1, n + 1):
		l = _getint(args, i)
		creq = data[p_pos:l]
		ret.append(ResetRequest(creq))
		p_pos = l
	return ret

def _parse_answer_enable_request(args):
	try:
		(sec, status) = args.split('\0', 1)
	except ValueError:
		raise BadAnswer('Missing \\0 (null byte)')
	if status not in ['True', 'False']:
		raise BadAnswer('Invalid active status \'%s\'' % status)
	if status == 'False':
		status = False
	else:
		status = True
	return (sec, status)

def _parse_answer_send_email(args):
	try:
		(raw_ok, raw_notok) = args.split('\0', 1)
	except ValueError:
		raise BadAnswer('Missing \\0 (null byte)')
	ok = raw_ok.split(' ')
	notok = raw_notok.split(' ')
	# needed if raw_ok is empty
	try:
		ok.remove('')
	except ValueError:
		pass
	try:
		notok.remove('')
	except ValueError:
		pass
	return (ok, notok)

_cmd2parse_answer = {
	'CREATEREQUEST': (_parse_simple_answer, []),
#	'GETREQUEST': (_parse_answer_get_request, []),  # Not implemented yet
	'LISTREQUESTS': (_parse_answer_list_requests, [a_ack]),
	'RESETPW': (_parse_simple_answer, []),
	'ENABLEREQUEST': (_parse_answer_enable_request, [a_ack]),
	'DISABLEREQUEST': (_parse_answer_enable_request, [a_ack]),
	'SENDEMAIL': (_parse_answer_send_email, [a_ack, a_nak]),
	'TESTPROTOCOL': (_parse_simple_answer, []),
}
def get_answer(conn, cmd):
	line = readpackets(conn)
	if line is None:
		raise BadAnswer('Empty answer')
	try:
		(status, args) = line.split(' ', 1)
	except ValueError:
		status = line.strip()
		args = None
	if status not in answer_list:
		raise ValueError('Unknown status `%s\'' % status)
	if status not in _cmd2parse_answer[cmd][1]:
		a_fnct = _parse_simple_answer
	else:
		a_fnct = _cmd2parse_answer[cmd][0]

	try:
		#answer = a_fnct(status, args)
		answer = a_fnct(args)
	except BadAnswer as e:
		raise BadAnswer(e.message, line)
	return (status, answer)


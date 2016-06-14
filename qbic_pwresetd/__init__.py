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


class GenericError(Exception):

	"""Base exception for this module"""

	def __init__(self, message):
		# Call the base class constructor with the parameters it needs
		super(GenericError, self).__init__(message)
		return

class ProtocolError(GenericError):
	
	"""
	To use with ow level protocol error or when connection should be closed
	and no answer should be given
	"""

	def __init__(self, message, errors = None):
		# Call the base class constructor with the parameters it needs
		super(ProtocolError, self).__init__(message)
		self.errors = errors
		return

	def __str__(self):
		return self.message

class ArgumentError(GenericError):

	"""
	Exception to use when a Procol valid incoming request cannot be honored
	for example because the requeseted username is not in LDAP.
	Answer should be sent to the client
	"""

	def __init__(self, message, client_message = None):
		# Call the base class constructor with the parameters it needs
		super(ArgumentError, self).__init__(message)
		self._cm = client_message
		return

	def __str__(self):
		return self.message

	def client_message(self):
		if self._cm is None:
			return self.message
		return self._cm

class BadRequest(GenericError):

	"""
	Used when client sent a request valid for low level protocol (packet level),
	but violates higher levels of the protocol. For example bad structs or base64
	values, or missing username= or email= in CREATEREQUEST.
	In general this is used when an answer can be sent to the client
	"""

class BadAnswer(GenericError):

	"""
	For the client side when a malformed answer is received
	"""

	def __init__(self, message, answer = None):
		super(BadAnswer, self).__init__(message)
		self.answer = answer

	def __str__(self):
		return self.message

a_ack = 'ACK'
a_nak = 'NAK'
a_badrequest = 'BADREQUEST'
a_error = 'ERROR'
answer_list = [a_ack, a_nak, a_badrequest, a_error]

####################
### Raw Protocol ###
####################

buf_size = 4096
# according to the python reference library documentation about socket.recv
# "For best match with hardware and network realities, the value of bufsize should
# be a relatively small power of 2, for example, 4096."
# Our goal here is to send just few L2 packets. Ethernet default MTU is 1500 bytes
# considering there is some overhead due to IP and TCP layers the bigger power
# of two inside a single L2 packet should be
packet_size = 2**10
packet_header_t = struct.Struct('<IQ')

# TODO make it faster? Maybe not, it's unused anyway
def readline(sock, maxlength = buf_size):
	ret = ''
	for i in range(maxlength):
		c = sock.recv(1)
		if len(c) == 0 or c == '\n':
			return ret
		ret += c
	raise ProtocolError('Called readline with %d maxlength but incoming data exceeded' % maxlength)

def readbytes(sock, size):
	ret = ''
	while len(ret) < size:
		buf = sock.recv(size - len(ret))
		if len(buf) == 0:
			if len(ret) != 0:
				raise ProtocolError('readbytes: connection closed while waiting for %d bytes' % (size - len(ret)))
			else:
				# client simply disconnected?
				return None
		ret += buf
	return ret

def readpackets(sock, maxpackets = 4):
	raw_packet = readbytes(sock, packet_size)
	if raw_packet is None:
		return None

	try:
		(version, cl) = packet_header_t.unpack(raw_packet[:packet_header_t.size])
	except struct.error as e:
		raise ProtocolError('readpackets: cannot unpack packet header')
	if cl == 0:
		raise ProtocolError('readpackets: packet content length equal to zero')
	if cl <= packet_size - packet_header_t.size:
		ret = raw_packet[packet_header_t.size:cl + packet_header_t.size]
	else:
		ret = raw_packet[packet_header_t.size:]
		remaining = cl + packet_header_t.size - packet_size
		n = remaining / packet_size + int(remaining % packet_size > 0)
		if n > maxpackets - 1:
			raise ProtocolError('readpackets: %d packets incoming (cl %d), but limit is set to %d' % (n + 1, cl, maxpackets))
		for i in range(n):
			ret += readbytes(sock, packet_size)
		# truncate to the correct size
		ret = ret[:cl]
	return ret

def sendpackets(sock, string):
	cl = len(string)
	if cl == 0:
		# not going to send an empty packet
		return
	total = packet_header_t.size + cl
	n = total / packet_size + int(total % packet_size > 0)
	if n == 1:
		sock.sendall(packet_header_t.pack(1, cl) + string)
	else:
		sock.sendall(packet_header_t.pack(1, cl) + string[:packet_size - packet_header_t.size])
		string = string[packet_size - packet_header_t.size:]
		for i in range(0, n - 2):
			sock.sendall(string[i * packet_size:(i + 1) * packet_size])
		sock.sendall(string[(n - 2) * packet_size:])
	# all data sent, add padding if required
	sock.sendall('\0'*(packet_size - total % packet_size))
	return

#############################
# Command arguments structs #
#############################

create_request_third_argument_t = struct.Struct('<I?')
crta_t = create_request_third_argument_t
uint_t = struct.Struct('<I')
def unpack_uint(b):
        return uint_t.unpack(b)[0]

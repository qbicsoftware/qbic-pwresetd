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

from . import config, ArgumentError

reader_ldap = None
pwadmin_ldap = None

example_user = {
	'uid': ['qbcldaptest'],
	'objectClass': ['top', 'person', 'posixAccount', 'utueZDVuser'],
	'loginShell': ['/bin/bash'],
	'uidNumber': ['1000018'],
	'gidNumber': ['1000001'],
	'gecos': ['QBICLDAP Test'],
	'sn': ['Test'],
	'homeDirectory': ['/home-link/qbcldaptest'],
	'mail': ['enrico.tagliavini@uni-tuebingen.de'],
	'givenName': ['QBICLDAP'],
	'cn': ['QBICLDAP Test'],
	'userPassword': ['invalid password hash'],
}

fake_ldap_users = {}

def add_fake_user(**kwargs):
	fake_ldap_users[kwargs['uid'][0]] = kwargs

def init_ldap(qbic_luri, pwadmin_bdn, pwadmin_bpwd, reader_bdn, reader_bpwd, qbic_lbase, qbic_ubase):
	#global qbic_ldap_uri, pwadmin_bind_dn, pwadmin_bind_pwd, reader_bind_dn, reader_bind_pwd, qbic_ldap_base, qbic_user_base
	#qbic_ldap_uri = qbic_luri
	#pwadmin_bind_dn = pwadmin_bdn
	#pwadmin_bind_pwd = pwadmin_bpwd
	#reader_bind_dn = reader_bdn
	#reader_bind_pwd = reader_bpwd
	#qbic_ldap_base = qbic_lbase
	#qbic_user_base = qbic_ubase
	return

def connect_reader_ldap():
	return

def connect_pwadmin_ldap():
	return

def disconnect_ldap():
	return

def get_account_attrs(search_filter, attrs):
	search_filter = search_filter.strip('()')
	# just trivial filters are supported
	(attribute, value) = search_filter.split('=', 1)
	ret = []
	for (k, v) in fake_ldap_users.iteritems():
		if attribute in v and value in v[attribute]:
			ret.append(dict([(x, v[x]) for x in attrs]))
	return ret

def get_attrs_from_uid(uid, attrs):
	res = get_account_attrs('uid=%s' % uid, attrs)
	if res is None or len(res) == 0:
		return None
	if len(res) > 1:
		# LDAP is really fscked up. Raise this so the program terminates and secure LDAP from any
		# further interaction, it's broken anyway
		raise RuntimeError('LDAP returned more than one element while searching for uid %s' % uid)
	return res[0]

def get_email_from_uid(uid):
	res = get_attrs_from_uid(uid, ['mail'])
	if res is None or len(res) == 0:
		return None
	return res['mail'][0] # if there is more than one we just get the first one

def get_uid_from_email(email):
	# more than one can be returned in principle
	uids = []
	for a in get_account_attrs('mail=%s' % email, ['uid']):
		uids += a['uids']
	return uids

def change_ldap_password(uid, new_password):
	return


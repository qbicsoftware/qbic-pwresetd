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

import ldap

from passlib.apps import ldap_context
from . import config, ArgumentError

ldap_crypto_context = "ldap_sha512_crypt"
reader_ldap = None
pwadmin_ldap = None

fake_ldap_uri = 'fakeldap'
qbic_ldap_uri = None
pwadmin_bind_dn = None
pwadmin_bind_pwd = None
reader_bind_dn = None
reader_bind_pwd = None
qbic_ldap_base = None
qbic_user_base = None

def init_ldap(qbic_luri, pwadmin_bdn, pwadmin_bpwd, reader_bdn, reader_bpwd, qbic_lbase, qbic_ubase):
	global qbic_ldap_uri, pwadmin_bind_dn, pwadmin_bind_pwd, reader_bind_dn, reader_bind_pwd, qbic_ldap_base, qbic_user_base
	global connect_reader_ldap, connect_pwadmin_ldap, disconnect_ldap, get_account_attrs, _change_ldap_password
	if qbic_luri == fake_ldap_uri:
		from . import fakeqbicldap
		# have the fake sneaking in (Enrico is a cheater :P)
		connect_reader_ldap = fakeqbicldap.connect_reader_ldap
		connect_pwadmin_ldap = fakeqbicldap.connect_pwadmin_ldap
		disconnect_ldap = fakeqbicldap.disconnect_ldap
		get_account_attrs = fakeqbicldap.get_account_attrs
		_change_ldap_password = fakeqbicldap.change_ldap_password
		# put some data in the DB
		fakeqbicldap.add_fake_user(**fakeqbicldap.example_user)
	else:
		qbic_ldap_uri = qbic_luri
		pwadmin_bind_dn = pwadmin_bdn
		pwadmin_bind_pwd = pwadmin_bpwd
		reader_bind_dn = reader_bdn
		reader_bind_pwd = reader_bpwd
		qbic_ldap_base = qbic_lbase
		qbic_user_base = qbic_ubase
	return

def _connect_to_qldap(uri, bind_as_user, password = None):
	qldap = ldap.initialize(uri,  trace_level=0)
	qldap.version = ldap.VERSION3
	#qldap.set_option(ldap.OPT_X_TLS_CACERTFILE, '/etc/pki/tls/certs/ca-bundle.crt')
	qldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
	qldap.start_tls_s()
	qldap.simple_bind_s(bind_as_user, password)
	return qldap

def connect_reader_ldap():
	global reader_ldap
	if reader_ldap is None:
		reader_ldap = _connect_to_qldap(qbic_ldap_uri, reader_bind_dn, reader_bind_pwd)
	return

def connect_pwadmin_ldap():
	global pwadmin_ldap
	if pwadmin_ldap is None:
		pwadmin_ldap = _connect_to_qldap(qbic_ldap_uri, pwadmin_bind_dn, pwadmin_bind_pwd)
	return

def disconnect_ldap():
	global reader_ldap
	global pwadmin_ldap
	if reader_ldap is not None:
		reader_ldap.unbind_s()
		reader_ldap = None
	if pwadmin_ldap is not None:
		pwadmin_ldap.unbind_s()
		pwadmin_ldap = None

def get_account_attrs(search_filter, attrs):
	connect_reader_ldap()
	if search_filter.startswith('(') and search_filter.endswith(')'):
		search_filter = search_filter[1:len(search_filter) - 1]
	res = reader_ldap.search_ext_s(
		qbic_ldap_base,
		ldap.SCOPE_SUBTREE,
		filterstr='(&(objectClass=posixAccount)(%s))' % search_filter,
		attrlist=attrs
	)
	if len(res) == 0:
		return None
	return [args for (dn, args) in res]

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
	#return 'enrico.tagliavini@uni-tuebingen.de'

def get_uid_from_email(email):
	# more than one can be returned in principle
	uids = []
	for a in get_account_attrs('mail=%s' % email, ['uid']):
		uids += a['uid']
	return uids
	#return ['qbictest01']

def _crypt_password(pwd):
	lc = ldap_context.replace(default=ldap_crypto_context)
	return lc.encrypt(pwd, rounds=5000, salt_size=16)

def _change_ldap_password(uid, new_password):
	connect_pwadmin_ldap()
	res = pwadmin_ldap.search_ext_s(qbic_user_base,
			ldap.SCOPE_SUBTREE,
			filterstr='(&(objectClass=posixAccount)(uid=%s))' % uid,
			attrlist=[]
	)
	if len(res) == 0:
		raise ArgumentError('No posixAccount found with uid=%s' % uid)
	if len(res) > 1:
		# LDAP is busted, terminate this daemon
		raise RuntimeError(
				'Found %d entries matching uid=%s:\n%s' % \
				(len(res), uid, '\n'.join([x[0] for x in res]))
		)
	dn = res[0][0]
	modlist = [(ldap.MOD_REPLACE, 'userPassword', _crypt_password(new_password))]
#	msg = 'Calling ldap modify to change userPassword field for %s' % dn
#	if config.testonly:
#		msg = '[TEST] ' + msg
#	logitout(msg, INFO)
	if not config.testonly:
		pwadmin_ldap.modify_ext_s(dn, modlist)
	return

def change_ldap_password(uid, new_password):
	return _change_ldap_password(uid, new_password)

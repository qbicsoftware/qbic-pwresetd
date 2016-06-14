import os
import sqlite3
import struct

from datetime import datetime, timedelta
from nose.tools import with_setup
from qbic_pwresetd import config
from qbic_pwresetd.fakeqbicldap import example_user
from qbic_pwresetd.resetrequest import ResetRequest, DBManager

import tests
from tests import account_name, secret, duration, active, creation_timestamp

# the safe-net testonly option for the main module must be disabled
# or all changes to the DB will be rolled back.
config.testonly = False

dbmanager = None

def setup_empty_db():
	global dbmanager
	tests.setup_empty_db()
	dbmanager = tests.dbmanager

def setup_db():
	global dbmanager
	tests.setup_db()
	dbmanager = tests.dbmanager

def teardown_db():
	global dbmanager
	dbmanager = None
	tests.teardown_db()

def resetrequest_init_test():
	# no exception should be rised here
	r1 = ResetRequest(
		account_name = account_name,
		secret_code = secret,
		duration = duration,
		active = active,
		creation_timestamp = creation_timestamp
	)
	r2 = ResetRequest(r1.pack())
	assert r1.account_name == r2.account_name
	assert r1.secret_code == r2.secret_code
	assert r1.duration == r2.duration
	assert r1.active == r2.active
	assert r1.creation_timestamp == r2.creation_timestamp
	# now we know the two are equal. Verify it's equal to the original
	assert r1.account_name == account_name
	assert r1.secret_code == secret
	assert r1.duration == duration
	assert r1.active == active
	assert r1.creation_timestamp == creation_timestamp
	# Now test wrong uses
	battery_test = [
		(('invalidstruct',), ValueError),  # this is too long, it's truncated and fails after the unpack()
		(('is',), struct.error),  # too short
		({'account_name': account_name}, TypeError),
		({'account_name': '', 'secret_code': ''}, TypeError),
		({'account_name': account_name, 'secret_code': secret, 'creation_timestamp': 'just a string'}, TypeError),
	]
	for (args, exception_type) in battery_test:
		print('Testing ResetRequest with args: %s, expecting exception %s' % (repr(args), exception_type.__name__))
		try:
			if type(args).__name__ == 'dict':
				ResetRequest(**args)
			else:
				ResetRequest(*args)
		except exception_type:
			pass
		else:
			assert False
	try:
		r2 = ResetRequest(r1.pack(), account_name = account_name)
	except TypeError:
		pass
	else:
		assert False

def expired_test():
	# expired
	r1 = ResetRequest(
		account_name = account_name,
		secret_code = secret,
		duration = duration,
		active = active,
		creation_timestamp = datetime.utcnow() - timedelta(hours = duration, seconds = 1)
	)
	assert r1.expired()
	# valid for one more hour
	r2 = ResetRequest(
		account_name = account_name,
		secret_code = secret,
		duration = duration,
		active = active,
		creation_timestamp = datetime.utcnow() - timedelta(hours = duration - 1)
	)
	assert not r2.expired()

def expiry_date_test():
	r1 = ResetRequest(
		account_name = account_name,
		secret_code = secret,
		duration = duration,
		active = active,
		creation_timestamp = creation_timestamp
	)
	assert r1.expiry_date() == creation_timestamp + timedelta(hours = duration)

def dbinit_test():
	setup_db()
	teardown_db()

@with_setup(setup_empty_db, teardown_db)
def add_request_test():
	r1 = ResetRequest(
		account_name = account_name,
		secret_code = secret,
		duration = duration,
		active = active,
		creation_timestamp = creation_timestamp
	)
	dbmanager.add_request(r1)
	assert len(dbmanager.list_requests()) == 1
	for r in dbmanager.list_requests():
		print(str(r))
	# be sure we cannot add a request with the same secret twice
	# first try to add exactly the same twice, then change only the secret
	try:
		dbmanager.add_request(r1)
	except sqlite3.IntegrityError:
		pass
	else:
		assert False
	r2 = ResetRequest(
		account_name = account_name,
		secret_code = 'anotheruniquesecret',
		duration = duration,
		active = active,
		creation_timestamp = creation_timestamp
	)
	dbmanager.add_request(r2)
	# now check what we entered is still equal to the original
	new_r1 = dbmanager.get_request(secret)
	assert r1.account_name == new_r1.account_name
	assert r1.secret_code == new_r1.secret_code
	assert r1.duration == new_r1.duration
	assert r1.active == new_r1.active
	assert r1.creation_timestamp == new_r1.creation_timestamp

@with_setup(setup_db, teardown_db)
def getrequest_test():
	r1 = dbmanager.get_request(secret)
	assert r1 is not None
	assert r1.account_name == account_name
	assert r1.duration == duration
	assert r1.active == active
	assert r1.creation_timestamp == creation_timestamp

@with_setup(setup_db, teardown_db)
def listrequests_test():
	l = dbmanager.list_requests(10)
	assert len(l) <= 10
	l = dbmanager.list_requests(1)
	assert len(l) <= 1

@with_setup(setup_db, teardown_db)
def update_request_by_secret_test():
	assert dbmanager.update_request_by_secret(secret, 'is_active', True) == 1
	# disable it again
	assert dbmanager.update_request_by_secret(secret, 'is_active', False) == 1

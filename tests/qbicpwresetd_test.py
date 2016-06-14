import qbicpwresetd

from datetime import datetime
from nose.tools import with_setup

from . import setup_ldap
from qbic_pwresetd.fakeqbicldap import example_user, change_ldap_password
from qbic_pwresetd.resetrequest import ResetRequest
from qbic_pwresetd import config, a_ack, a_nak, a_badrequest, a_error, ArgumentError, BadRequest
from qbicpwresetd import secret_sanitize_re, create_request, check_and_passwd, enable_request, disable_request

import tests
from tests import account_name, secret, valid_active_secret, valid_inactive_secret, expired_secret, duration, active, creation_timestamp

# define some config parameters normally passed via config file
qbicpwresetd.max_duration = 24*7
dbmanager = None

def setup_empty_db():
	global dbmanager
	tests.setup_empty_db()
	dbmanager = tests.dbmanager

def setup_db():
	global dbmanager
	tests.setup_db()
	dbmanager = tests.dbmanager
	qbicpwresetd.db_manager = tests.dbmanager

def teardown_db():
	global dbmanager
	dbmanager = None
	tests.teardown_db()

def setup_ldap_and_db():
	setup_db()
	setup_ldap()

@with_setup(setup_ldap)
def create_request_test():
	# we test the DB in another test, here just test the function body
	config.testonly = True
	# first test successful cases
	battery_test = [
		((None, 'username=' + example_user['uid'][0], 'autogenerate', duration, active), 64),
		((None, 'email=' + example_user['mail'][0], 'autogenerate', duration, active) ,64),
		((None, 'username=' + example_user['uid'][0], 'verylongvalidsecretverylongvalidsecret', duration, active), 38),
	]
	for (args, secret_len) in battery_test:
		(status, secret) = create_request(*args)
		assert status == a_ack
		assert len(secret) == secret_len
		assert secret_sanitize_re.search(secret) is None  # just to be sure\

	(status, secret) = create_request(None, 'username=' + example_user['uid'][0], 'autogenerate', duration, active)
	assert status == a_ack
	assert len(secret) == 64  # sha256 length
	assert secret_sanitize_re.search(secret) is None  # just to be sure
	(status, secret) = create_request(None, 'email=' + example_user['mail'][0], 'autogenerate', duration, active)
	assert status == a_ack
	assert len(secret) == 64  # sha256 length
	assert secret_sanitize_re.search(secret) is None  # just to be sure

	# now test failures
	battery_test_error = [
		((None, 'user', 'autogenerate', duration, active), ValueError),  # wrong first arg
		((None, 'user=', 'autogenerate', duration, active), ValueError),  # empty user
		((None, 'user=user', 'autogenerate', duration, active), ValueError),  # wrong first arg
		((None, 'username=user', 'autogenerate', duration, active), ArgumentError),  # username doesn't exist in LDAP
		((None, 'email=', 'autogenerate', duration, active), ArgumentError),  # empty email
		((None, 'email=user@example.org', 'autogenerate', duration, active), ArgumentError),  # username doesn't exist in LDAP
		((None, 'username=' + example_user['uid'][0], 'weaksecret', duration, active), ArgumentError),
		((None, 'username=' + example_user['uid'][0], 'secret with forbidden chars ; ? ! :(){ :|:& };:', duration, active), BadRequest),
		((None, 'username=' + example_user['uid'][0], 'autogenerate', qbicpwresetd.max_duration + 1, active), ArgumentError),

	]
	for (args, exception_type) in battery_test_error:
		try:
			create_request(*args)
		except exception_type:
			pass
		except Exception as e:
			print('Expecting exception %s but got %s for args %s' % (exception_type.__name__, type(e).__name__, repr(args)))
			assert False
		else:
			print('Didn\'t got exception %s for args %s' % (exception_type.__name__, repr(args)))
			assert False

@with_setup(setup_ldap_and_db, teardown_db)
def check_and_passwd_test():
	qbicpwresetd.invalid_credential_delay = 0
	qbicpwresetd.pwd_min_score = 12
	# silence stderr... cheater
	qbicpwresetd.logiterr = qbicpwresetd.logitout
	good_password = 'baghah9Hochiec7zee0lohQu'
	corrupted_username_secret = 'corruptedusername'
	# add an entry to the DB with no user matching LDAP, to simulate
	# LDAP / DB corruption
	dbmanager.add_request(ResetRequest(
		account_name = account_name,
		secret_code = corrupted_username_secret,
		duration = duration,
		active = True
	))
	#test exception rising
	battery_test_exceptions = [
		((None, example_user['uid'][0], 'no such sec exists', good_password), ArgumentError, 'Invalid credentials'),
		((None, 'wrong username', valid_active_secret, good_password), ArgumentError, 'Invalid credentials'),
		((None, example_user['uid'][0], valid_inactive_secret, good_password), ArgumentError, 'Invalid credentials'),
		((None, example_user['uid'][0], expired_secret, good_password), ArgumentError, 'Request expired'),
		((None, example_user['uid'][0], valid_active_secret, 'password'), ArgumentError, None),
		((None, example_user['uid'][0], valid_active_secret, 'ohqueiKuo7o'), ArgumentError, 'Weak password'),
	]
	for (args, exception_type, message) in battery_test_exceptions:
		print(
			'Testing with args %s, expecting expection %s %s' % (
				repr(args),
				exception_type.__name__,
				'with message %s' % repr(message) if message is not None else ''
			)
		)
		try:
			check_and_passwd(*args)
		except exception_type as e:
			if message is not None:
				assert e.client_message() == message
		except Exception as e:
			print('Expecting exception %s but got %s for args %s' % (exception_type.__name__, type(e).__name__, repr(args)))
			assert False
		else:
			print('Didn\'t got exception %s for args %s' % (exception_type.__name__, repr(args)))
			assert False
	# test failures without exception
	battery_test_error = [
		((None, account_name, corrupted_username_secret, good_password), a_error),
	]
	for (args, ret) in battery_test_error:
		assert check_and_passwd(*args)[0] == ret
	
	# finally test the successful case
	assert check_and_passwd(None, example_user['uid'][0], valid_active_secret, good_password)[0] == a_ack
	# and try again, the second time it must not work, secret should be valid only once
	try:
		check_and_passwd(None, example_user['uid'][0], valid_active_secret, good_password)
	except ArgumentError as e:
		assert e.client_message() == 'Invalid credentials'

@with_setup(setup_db, teardown_db)
def enable_request_test():
	# check twice to be sure the DB is not upset we don't update a row
	(ack, answer) = enable_request(None, secret)
	assert ack == a_ack
	(sec, enabled) = answer
	assert sec == secret
	assert enabled == True
	(ack, answer) = enable_request(None, secret)
	assert ack == a_ack
	(sec, enabled) = answer
	assert sec == secret
	assert enabled == True
	# now disable it
	(ack, answer) = disable_request(None, secret)
	assert ack == a_ack
	(sec, enabled) = answer
	assert sec == secret
	assert enabled == False

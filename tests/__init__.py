import os

from datetime import datetime
from tempfile import NamedTemporaryFile, mkstemp

from qbic_pwresetd.qbicldap import fake_ldap_uri, init_ldap
from qbic_pwresetd.fakeqbicldap import example_user
from qbic_pwresetd.resetrequest import ResetRequest, DBManager
from qbic_pwresetd import config

dbmanager = None
tmpdb_path = None

account_name = 'user'
secret = 'secret'
valid_active_secret = 'testvalidactivesecret'
valid_inactive_secret = 'testvalidinactivesecret'
expired_secret = 'testexpiredsecret'
duration = 48
active = False
creation_timestamp = datetime(2016, 1, 1, 0, 0, 1)

def setup_ldap():
	init_ldap(fake_ldap_uri, '', '', '', '', '', '')

def setup_empty_db():
	global tmpdb_path
	global dbmanager
	# force testonly to false. If we cannot write to the DB we cannot go ahead
	config.testonly = False
	(db_fd, tmpdb_path) = mkstemp(prefix = 'pwresetd_dbinit_test')
	dbmanager = DBManager('sqlite', tmpdb_path, rrequests_table = 'rrequests_table')
	dbmanager.connect()

def setup_db():
	setup_empty_db()
	dbmanager.add_request(ResetRequest(
			account_name = account_name,
			secret_code = secret,
			duration = duration,
			active = active,
			creation_timestamp = creation_timestamp
		)
	)
	dbmanager.add_request(ResetRequest(
			account_name = example_user['uid'][0],
			secret_code = valid_active_secret,
			duration = 48,
			active = True
		)
	)
	dbmanager.add_request(ResetRequest(
			account_name = example_user['uid'][0],
			secret_code = valid_inactive_secret,
			duration = 48,
			active = False
		)
	)
	dbmanager.add_request(ResetRequest(
			account_name = example_user['uid'][0],
			secret_code = expired_secret,
			duration = 48,
			creation_timestamp = creation_timestamp,
			active = True
		)
	)

def teardown_db():
	global dbmanager
	if dbmanager is not None:
		dbmanager.disconnect()
		dbmanager = None
	if tmpdb_path is not None:
		os.unlink(tmpdb_path)

from qbic_pwresetd.fakeqbicldap import *

def get_account_attrs_test():
	add_fake_user(**example_user)
	assert get_email_from_uid(example_user['uid'][0]) == example_user['mail'][0]

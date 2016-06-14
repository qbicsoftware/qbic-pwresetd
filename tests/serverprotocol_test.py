from base64 import standard_b64encode, standard_b64decode

from qbic_pwresetd.serverprotocol import _parse_create_request, _parse_reset_password
from qbic_pwresetd import crta_t, BadRequest

def _test_parser(p_funct, args, results):
	print('Testing \'%s\' with args %s. Expected result is %s' % (p_funct.__name__, repr(args), repr(results)))
	p_res = p_funct(args)
	assert len(p_res) == len(results)
	for i in xrange(len(results)):
		assert results[i] == p_res[i]

def _test_parser_error(p_funct, args, exception_type, message = None):
	print('Testing \'%s\' with args %s. Expected exception is %s' % (p_funct.__name__, repr(args), exception_type.__name__))
	try:
		p_res = p_funct(args)
	except exception_type as e:
		if message is not None:
			assert e.message == message
	else:
		assert False

def parse_create_request_test():
	t_battery = [
		(['username=someone', 'secret', crta_t.pack(48, False)], ('username=someone', 'secret', 48, False)),
		(['email=' + standard_b64encode('user@example.com'), 'secret', crta_t.pack(48, False)], ('email=user@example.com', 'secret', 48, False)),
	]
	for (arg, res) in t_battery:
		_test_parser(_parse_create_request, arg, res)
	
	t_error_battery = [
		# wrong username
		(['someone', 'secret', crta_t.pack(48, False)], BadRequest),
		# email not encoded correctly
		(['email=someone@example.org', 'secret', crta_t.pack(48, False)], BadRequest),
		# invalid char in secret
		(['user=someone', 'secret;', crta_t.pack(48, False)], BadRequest),
		# invalid third arg
		(['user=someone', 'secret', 'invalid pack'], BadRequest),
		
	]
	for (arg, res) in t_error_battery:
		_test_parser_error(_parse_create_request, arg, res)

def parse_reset_password_test():
	t_battery = [
		(['someone', 'secret', standard_b64encode('new_password')], ('someone', 'secret', 'new_password'))
	]
	for (arg, res) in t_battery:
		_test_parser(_parse_reset_password, arg, res)
	
	t_error_battery = [
		# password not base64 encoded
		(['someone', 'secret', 'new_password'], BadRequest)
	]
	for (arg, res) in t_error_battery:
		_test_parser_error(_parse_reset_password, arg, res)

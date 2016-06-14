#!/usr/bin/env python

from setuptools import setup

### This is from iotop setup.py
# Dirty hack to make setup.py install the iotop script to sbin/ instead of bin/
# while still honoring the choice of installing into local/ or not.
#if hasattr(distutils_install, 'INSTALL_SCHEMES'):
#	for d in distutils_install.INSTALL_SCHEMES.itervalues():
#		if d.get('scripts', '').endswith('/bin'):
#			d['scripts'] = d['scripts'][:-len('/bin')] + '/sbin'

setup(
	name = 'qbic_pwresetd',
	version = '1.0.2',
	description = 'QBiC password reset daemon',
	long_description = 'Password reset daemon for QBiC web services',
	author = 'Enrico Tagliavini',
	author_email = 'enrico.tagliavini@uni-tuebingen.de',
	url = 'https://portal.qbic.uni-tuebingen.de/',
	packages = ['qbic_pwresetd'],
	license = 'LGPL 2.1',
	platforms = 'linux',

	# sorry but deps should be handled by the package manager
	# MySQL-python was kind of forked and it's not always picked up
	# pwquality is not picked up at all. As a matter of fact
	# this doesn't work.
	# Requires: python-ldap, MySQL-python (MySQLdb), python-pwquality, passlib, pytz, systemd-python
	#install_requires = ['MySQL-python', 'passlib', 'pytz'],

	scripts = [
		'src/qbic-pwresetd',
		'src/pwreset',
	],
	zip_safe = False,
)


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

import pwquality

from math import exp, log

pwq = pwquality.PWQSettings()
pwq.read_config()
pwq.set_option('badwords=')
pwq.set_option('gecoscheck=0')
pwq.set_option('maxrepeat=3')

leet_dict = {
	'1': 'i',
	'2': 'z',
	'3': 'e',
	'4': 'a',
	'5': 's',
	'6': 'g',
	'7': 't',
	'8': 'b',
	'9': 'g',
	'0': 'o',
	'@': 'a',
	'$': 's',
}
def remove_leet(word):
	for l in leet_dict.iterkeys():
		word = word.replace(l, leet_dict[l])
	return word

def longest_common_substring(s1, s2):
	m = [[0] * (1 + len(s2)) for i in xrange(1 + len(s1))]
	longest, x_longest = 0, 0
	for x in xrange(1, 1 + len(s1)):
		for y in xrange(1, 1 + len(s2)):
			if s1[x - 1] == s2[y - 1]:
				m[x][y] = m[x - 1][y - 1] + 1
				if m[x][y] > longest:
					longest = m[x][y]
					x_longest = x
			else:
				m[x][y] = 0
	return s1[x_longest - longest: x_longest]

def similar(passwd, word):
	lcsl = len(longest_common_substring(passwd, word))
	if lcsl <= 3: # threshold
		return 0
	return lcsl - 1

def pwq_score(passwd):
	try:
		ret = pwq.check(passwd)
	except pwquality.PWQError as e:
		return (-1, e)
	return (ret, None)

def pwd_score(passwd, badwords):
	# convert everything to lower case
	passwd = passwd.lower()
	badwords = [x.lower() for x in badwords]
	my_score = len(passwd)

	for w in badwords:
		my_score -= max(similar(passwd, w), similar(remove_leet(passwd), w))
	
	pwq.set_option('badwords=%s' % ' '.join(badwords))
	(q_score, pwq_error) = pwq_score(passwd)
	(q_score_leet, pwq_error_leet) = pwq_score(remove_leet(passwd))
	if q_score_leet < q_score:
		q_score = q_score_leet
		pwq_error = pwq_error_leet
	
	# fail immediately if one of the checks in pwquality triggered
	if q_score <= 0:
		return (-1, pwq_error.args[1])
	
	# normalize q_score for our purpose. A 12 char password from pwgen seems to have 
	# a score around 45 (for from 44 to 50). We are ok with that.... 12 char password
	# is already next to impossible for the average user
	q_score = q_score / 0.44
	#q_score = int((1 + 1.0 / (1.0 - exp(6 * float(q_score) / 100 + log(2)))) * 100)
	#q_score = int((1.24 + 1.0 / (1.0 - exp(2 * float(q_score) / 100 + log(2)))) * 100)
	
	score = min(100 * my_score / len(passwd), q_score)
	#print('%s score: %d, PWQ score: %d' % (passwd, my_score, len(passwd) * q_score / 100))
	return (score * len(passwd) / 100, None)


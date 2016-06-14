from qbic_pwresetd.pw_check import pwd_score

badwords = ['Enrico', 'Tagliavini']

def catch_badword_test():
	assert pwd_score('enricotagliavinirocks', badwords)[0] == -1
	assert pwd_score('3nr1c0t4gl14v1n1r0cks', badwords)[0] == -1
	assert pwd_score('enrictagliavrocks', badwords)[0] <= 7  # pwquality will not catch this

def dictionary_test():
	assert pwd_score('password15', badwords)[0] == -1
	assert pwd_score('princess84', badwords)[0] == -1

def good_password_test():
	assert pwd_score('Fooyeeph7eiw', badwords)[0] >= 12
	assert pwd_score('OopiD9riel8u', badwords)[0] >= 12
	assert pwd_score('WaiciT2ija3s', badwords)[0] >= 12
	assert pwd_score('doofohGooPh0xohd', badwords)[0] >= 16
	assert pwd_score('baghah9Hochiec7zee0lohQu', badwords)[0] >= 24

def repeat_for_length_test():
	assert pwd_score('repeatforlength1111111111111', badwords)[0] == -1
	assert pwd_score('asdasdasdasdasd', badwords)[0] == -1

# QBiC Password reset daemon

This is the password reset daemon implementing the password reset service for the QBiC Web Portal and related services. It implements the classic reset procedure sending an email to the user with a one time use URL to change the password. This package includes only the daemon part, the web interface is provided by a separate software, but in principle it can be anything implementing the same protocol.

# Dependencies:
 * python 2.7
 * python-ldap
 * MySQL-python (MySQLdb)
 * python-pwquality
 * passlib
 * pytz
 * systemd-python

# Development setup

 * create the MySQL DB with
    `$ sql/dump_and_create_db.sh password_reset_request qbic-pwadmin`
 * create a config file from the template in *cfg/*, place somewhere, for example *${HOME}/.local/etc/qbic-ldap-pwd-resetd.ini*
 * install and run it
    `$ python setup.py install --user && qbic-pwresetd -c ${HOME}/.local/etc/qbic-ldap-pwd-resetd.ini --test`

Better to install the package with the python user scheme for easy test / development. DON'T RUN setup.py AS ROOT! Generate a package instead, we provide a spec file.

Don't forget to run the test suite with
    `$ nosetests --no-byte-compile ./tests`

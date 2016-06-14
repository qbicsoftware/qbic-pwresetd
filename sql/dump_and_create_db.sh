#!/bin/bash

set -eu

help_text="Usage:
	$0 dbname dbuser

to create a database named dbname and grant all privileges to dbuser@localhost.
WARNING: this will dump the DB if it exists already!
"

usage() {
	echo "${help_text}"
}

if [ $# -ne 2 ] ; then
	usage
	exit 1
fi

SQL_CMDS=$(sed "s/@DB_NAME@/${1}/ ; s/@DB_USER@/${2}/" "${0%/*}"/create_request_db.sql)
echo "${SQL_CMDS}" | mysql -u root -p


#!/bin/bash

# This is a sample shell script which is triggered when a password is found. You can configure john to 
# execute it by uncommenting "ExecOnCrackedPassword" key in john.conf
# 
# Note: john would pass login name if "PassArgLogin" is set to Y in john.conf (default), and 
# plain password, if "PassArgPassword" is set to Y.


while getopts ":l:p:" opt; do
    case $opt in
	l) login="$OPTARG"
	;;
	p) passwd="$OPTARG"
	;;
    esac
done

echo "Password found"
if [ ! -z "$login" ]; then
    echo "  login: $login"
fi

if [ ! -z "$passwd" ]; then
    echo "  password: $passwd"
fi
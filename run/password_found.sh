#!/bin/bash

# This is a sample shell script which is triggered when a password is found. You can configure john to 
# execute it by uncommenting "ExecOnCrackedPassword" key in john.conf
# 
# Note: john would pass login name as first argument if "PassArgLogin" is set to Y in john.conf (default), and 
# plain password as second argument, if "PassArgPassword" is set to Y.

echo "Password found for user $1" # and password is $2

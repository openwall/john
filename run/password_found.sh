#!/bin/bash

# This is a sample shell script which is triggered when a password is found. You can configure john to 
# execute it by uncommenting "ExecOnCrackedPassword" key in john.conf

echo "Password found for $1: $2"

#!/usr/bin/python

"""

Dumping APEX hashes
===================

1. Automated Way

C:\apex>sqlplus sys as sysdba

SQL*Plus: Release 11.2.0.2.0 Production on Fri Feb 22 17:20:51 2013

Copyright (c) 1982, 2010, Oracle.  All rights reserved.

Enter password:

Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - Production

SQL> @dump-apex-hashes.sql

$ python apex2john.py apex-hashes.txt > apex-hashes-JtR

$ john pex-hashes-JtR # use JtR-jumbo from https://github.com/openwall/john/
Loaded 1 password hash (dynamic_1: md5($p.$s) (joomla) [128/128 SSE2 intrinsics 10x4x3])
password         (?)
guesses: 1  time: 0:00:00:00 DONE (Thu Feb 21 17:33:43 2013)  c/s: 375  trying: 123456 - boomer

2. Manual Way

SQL> alter session set current_schema = APEX_040200;

Session altered.

SQL> select user_name,web_password2,security_group_id from wwv_flow_fnd_user;

USER_NAME
--------------------------------------------------------------------------------
WEB_PASSWORD2
--------------------------------------------------------------------------------
SECURITY_GROUP_ID
-----------------
ADMIN
F96D32CBB2FBE17732C3BBAB91C14F3A
10

...

$ cat dump-apex-hashes.sql
set colsep ','
set echo off
set feedback off
set linesize 1000
set pagesize 0
set sqlprompt ''
set trimspool on
set headsep off
set termout off
alter session set current_schema = APEX_040200;
spool "apex-hashes.txt"
select user_name,web_password2,security_group_id from wwv_flow_fnd_user;
spool off

"""

import hashlib

username = "ADMIN"
sgid = "10"
password = "password"

# APEX 4.2.1 algorithm
print username, sgid, password, hashlib.md5(password + sgid + username).hexdigest()

# should print "f96d32cbb2fbe17732c3bbab91c14f3a" which is the actual hash

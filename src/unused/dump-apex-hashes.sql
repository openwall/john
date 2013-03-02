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
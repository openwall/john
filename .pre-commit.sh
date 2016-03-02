#!/bin/sh
#
#######################################################
# This is a git pre-commit hook. It is a local hook,
# BUT will do nothing until installed on your local
# git repo.
#
# To install:
#   ln -s ../../.pre-commit.sh .git/hooks/pre-commit
#
#######################################################
# enforcement of JtR requirements for:
#   1. Disallow source with exec bit set
#   2. Disallow scripts without exec bit set
#   3.  .... (add more checks when problems arise)
#######################################################

########################################################
# test 1. Make sure source does not have execute bit set
########################################################
TXT_FILE_PATTERN='\.(cl|c|h|txt|S|s|in|chr|conf)(\..+)?$'
TXT_LISTING=`git diff --cached --name-only | grep -E $TXT_FILE_PATTERN`
if [ "x$TXT_LISTING" != "x" ] ; then
TXT_LISTING=`echo "$TXT_LISTING" | xargs ls -l`
echo "$TXT_LISTING" | cut -b 4 | grep -q x && \
	echo 'COMMIT REJECTED Found src/text files WITH execute bit set:' && echo "$TXT_LISTING" | grep ^-..x && exit 1
fi

########################################################
# test 2. Make sure scripts have execute bit set
########################################################
SCRIPT_FILE_PATTERN='\.(pl|py|sh)(\..+)?$'
SCRIPT_LISTING=`git diff --cached --name-only | grep -E $SCRIPT_FILE_PATTERN`
if [ "x$SCRIPT_LISTING" != "x" ] ; then
SCRIPT_LISTING=`echo "$SCRIPT_LISTING" | xargs ls -l`
echo "$SCRIPT_LISTING" | cut -b 4 | grep -v -q x && \
	echo 'COMMIT REJECTED Found script files WITHOUT execute bit set:' && echo "$SCRIPT_LISTING" | grep ^-..- && exit 1
fi

return 0
#!/bin/sh
#
# This file is part of John the Ripper password cracker,
# Copyright (c) 1996-98 by Solar Designer
#
# This is a script to send mail to all users whose passwords got cracked.
# This is not always a good idea, though, since lots of people do not
# check their e-mail or ignore such messages, and the messages can be a
# hint for crackers.
#
# You should probably deploy proactive password strength checking, such as
# with passwdqc, before you ask users to change their passwords - whether
# using this script or otherwise.  And you should edit the message inside
# the script before possibly using it.
#

if [ $# -ne 1 ]; then
	echo "Usage: $0 PASSWORD-FILE"
	exit 0
fi

# There's no need to mail users with these shells
SHELLS=-,/bin/false,/dev/null,/bin/sync

# Look for John in the same directory with this script
DIR="`echo "$0" | sed 's,/[^/]*$,,'`"

# Let's start
$DIR/john -show "$1" -shells:$SHELLS | sed -n 's/:.*//p' |
(
	SENT=0

	while read LOGIN; do
		echo Sending mail to "$LOGIN"...

# You'll probably want to edit the message below
		mail -s 'Bad password' "$LOGIN" << EOF
Hello!

Your password for account "$LOGIN" is insecure.  Please change it as soon
as possible.

Yours,
	Password Checking Robot.
EOF

		SENT=$(($SENT+1))
	done

	echo $SENT messages sent
)

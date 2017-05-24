#!/bin/sh
#
# Test flock(2) using flock(1)
#
# NOTE: If you use NFS, there's more to it than running just this test script:
# An NFS mount should be tested first by running this script on the server (on
# its real filesystem, e.g., ext4) and then on a client, and lastly by locking
# a file on the server (eg. using "flock -x .lockfile sleep 300") and while
# that lock is in place, run this script on a client in whatever mounted
# directory is pointing to the *same* "physical" directory on the server.
# If the script happily claims it got its own lock although the server already
# had one, congratulations: You are starting to become aware of the problems
# we need to be aware of... Luckily, if you do a similar test between two
# *clients* the result should be better.

LOCKFILE=.lockfile

if $(flock -n -x $LOCKFILE true); then
	echo "File initially not locked."
else
	echo "File is locked already. Waiting..."
	flock -s $LOCKFILE true
fi
echo "Locking file exclusively, using flock(2) for 5 seconds."
flock -x $LOCKFILE sleep 5 &
sleep 1
if $(flock -n -x $LOCKFILE true); then
	echo "Nope, it's not locked! Locking is b0rken."
else
	echo "Confirmed, file is locked. Waiting for shared lock..."
	flock -s $LOCKFILE echo "Got it, now releasing."
fi

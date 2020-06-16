Cracking bitcoin-qt (bitcoin) wallet files with john
====================================================

1. Run bitcoin2john.py on Bitcoin or some altcoin wallet file(s).

E.g. $ ../run/bitcoin2john.py wallet.dat >> hashes

2. Run john on the output of the bitcoin2john.py script.

E.g. $ ../run/john hashes

3. Wait for the password(s) to get cracked.

Notes:

This procedure also works with many altcoins historically forked from Bitcoin.

The bitcoin2john.py script is compatible with both Python 2 and Python 3.

Since Python 3 no longer provides Berkeley DB support out of the box, to get
the script to work with Python 3 you need to install the corresponding module:

pip3 install bsddb3

(maybe with "sudo", depending on your setup).

For the command above to work you also need to have Berkeley DB itself
installed first, so e.g. on Fedora you need to start by running:

sudo dnf install libdb-devel python3-devel

The version of Berkeley DB in use by your system's Python interpreter needs to
be compatible with the version in use by the wallet.  Unfortunately, this is
sometimes not the case.  For example, if you receive the message "unsupported
btree version: 10" from bitcoin2john.py, this means your altcoin wallet uses
Berkeley DB version 6 or newer whereas your Python interpreter probably uses
version 4 or 5 (as commonly provided by distributions for licensing reasons,
because version 6 switched to a more restrictive license).  How to get around
this is system-specific, but in general your options are building a suitable
version of Berkeley DB and Python's bsddb3 from source, or moving to another
system that might have the right versions packaged.

deathmorlock and Claudio Andre provided the below instructions for Ubuntu, for
use in a throw-away VM or container (since this messes with the system badly):

sudo apt update
sudo apt install python3 python3-pip

wget https://download.oracle.com/berkeley-db/db-6.2.32.NC.tar.gz
tar xzf db-6.2.32.NC.tar.gz
cd db-6.2.32.NC/build_unix
../dist/configure --prefix /usr/local/berkeley-db/6.2.32
sudo make install

# Ubuntu upstream version is bsddb3-6.2.7. So:
YES_I_HAVE_THE_RIGHT_TO_USE_THIS_BERKELEY_DB_VERSION=1 BERKELEYDB_DIR=/usr/local/berkeley-db/6.2.32 sudo pip3 install bsddb3

Alternatively to the above command, the following was also tested:

sudo echo YES_I_HAVE_THE_RIGHT_TO_USE_THIS_BERKELEY_DB_VERSION=1 >> /etc/environment
sudo echo BERKELEYDB_DIR=/usr/local/berkeley-db/6.2.32 >> /etc/environment

wget https://files.pythonhosted.org/packages/fa/ad/eb82bcccbfb076b6a6797f48c339460699103065fb2a2fc72403b16970fe/bsddb3-6.2.7.tar.gz
tar xzf bsddb3-6.2.7.tar.gz
cd bsddb3-6.2.7
sudo python3 setup.py install

Once again, the above complicated procedure is only needed if you receive the
"unsupported btree version: 10" error.  For regular Bitcoin wallets and many
altcoin wallets, you would not have that error and the procedure is unneeded.
It's only needed for some other altcoins.  Also, you should know what you're
doing, and in particular you might need to adjust these instructions to match
your system and the changing library versions and download locations.  These
instructions are an example and not something that will work for you as-is.

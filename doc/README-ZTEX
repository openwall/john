---------
Overview
---------
If you have ZTEX boards USB-FPGA 1.15y, you can use them with JtR.
Available "formats" are descrypt-ztex, bcrypt-ztex, sha512crypt-ztex,
Drupal7-ztex, sha256crypt-ztex, md5crypt-ztex, phpass-ztex.

-------------
How to build
-------------
To build JtR bleeding-jumbo with ZTEX 1.15y board support, install
libusb (e.g., the libusb-devel package on Fedora) in addition to jumbo's
usual dependencies.  Then use "./configure --enable-ztex".  The rest of
the build is as usual for jumbo.

---------------
Usage on Linux
---------------
To access a ZTEX board as non-root (and you shouldn't build nor run JtR
as root) on a Linux system with udev, add this:

ATTRS{idVendor}=="221a", ATTRS{idProduct}=="0100", SUBSYSTEMS=="usb", ACTION=="add", MODE="0660", GROUP="ztex"

e.g. to /etc/udev/rules.d/99-local.rules (create this file).  Then issue
these commands as root:

groupadd ztex
usermod -a -G ztex user # where "user" is your non-root username
systemctl restart systemd-udevd # or "service udev restart" if without systemd

In order to trigger udev to set the new permissions, (re)connect the
device after this point.

-----------------
Usage on Windows
-----------------
It requires WinUSB driver to access the board.
You can install the driver using Zadig 2.2 software.

----------------------
Format Specific Notes
----------------------
descrypt-ztex. That's a fast "format", USB 2.0 is unable to transfer
password candidates from the host at the rate they are computed.
Use mask mode to allow on-board candidate generation.
Other feature is the limit of no more than 2,047 hashes per salt.

bcrypt-ztex. You have to adjust TargetSetting in john.conf,
section [ZTEX:bcrypt] to reflect settings of your hashes.
Big difference between TargetSetting and setting of your hashes
would result in performance degradation or timeout.

sha512crypt-ztex, Drupal7-ztex. These 2 formats use same bitstream.
You'll have to adjust TargetRounds in john.conf in sections
[ZTEX:sha512crypt], [ZTEX:Drupal7] to reflect approximate rounds
setting of your hashes.

-----------------------------
Runtime Frequency Adjustment
-----------------------------
Frequency adjustment is available. You can set non-default frequency
in john.conf on per-format basis, in section [ZTEX:format_name].
Extreme overclocking results in some guesses being lost without notice,
you should check if 100% of test passwords are found at given frequency.
More overclocking results in errors. On error, JtR resets the board
while other boards continue operating. If there's a single board then
it waits until the board is up.

---------------------------
Troubleshooting ZTEX board
---------------------------
You can test the board using Ztex SDK. There are example applications
and FWLoader maintenance utility (requires java runtime).
Version ztex-140813b from http://www.ztex.de/ is known to work.
As 1.15y board is out of production, newer SDK versions might have limited
support for this board.

---------------
Various Issues
---------------
You can select a limited set of boards using "--devices" command-line
option (i.e. --dev=04A36E0000,04A36D0000). Several instances of john
each one with its own set of boards can be invoked. Right now such usage
is considered experimental - on some USB subsystems several instances
conflict one with another and errors appear.

Each board has a factory programmed Serial Number (SN). JtR displays
SNs on startup and in information/error messages. To hide SNs, you can
list SNs of your boards in [List.ZTEX:Devices] section in john.conf.
Board numbers (starting from 1) will appear instead of SNs. You can
specify these numbers in --dev command-line option.


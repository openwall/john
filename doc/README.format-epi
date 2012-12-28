= Intro
=======

EPiServer is a popular webbased content management system from Elektropost (http://www.episerver.com).
You can dump the password hashes using the SQL syntax "select name, salt, hash from tblSID". The tblSID
tabel stores interesting things such as usernames, salt and password hashes, but also passwords in cleartext.
If a password can be found in cleartext it is found in the password column of tblSID.

= Usage
=======

The format of the password file needs to be: <user>:<salt> <hash>. (Currently you need to include
an inital 0x of both salt and hash.)

--- Contents of an example epipasswd file ---

webadmin:0x6631F625DEC28716FC24FA3CC1B3E2055E4281F4465226905C10D3456035 0x4F25D9BD24B81D85B1F2D106037C71CD2C828168
epiuser:0x48F9BA13F54CE7AF669C76EEBC6BEA4564EBB77F1866CA5F2B297F7159C1 0xDA4260812C195025B4442C5C84E0F890122B285A

-------------- End --------------------------

You can then run "john epipasswd", the format will be autodetected.
In case you'd like to check the performance of the patch try "john --test --format:epi".

-johannes

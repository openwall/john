Cracking IOS 7 restrictions PIN code
====================================

1. Fetch the file com.apple.restrictionspassword.plist from your phone. How
   you do this is out of scope for this document, just google it.


2. Run ios7tojohn on that file, redirecting output to a new file. Eg:

   $ ./ios7tojohn com.apple.restrictionspassword.plist > ioshash


3. Run john on the new file, only using four digits (it's a PIN code):

   $ ./john ioshash -inc:digits -min-len=4 -max-len=4


4. The password will get cracked in a split second. This is not because Apple
   used a very poor hash mechanism but because the keyspace of a PIN code is
   so very tiny.

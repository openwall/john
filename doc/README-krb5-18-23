================================================================================
This patch is Copyright (c) 2012, Mougey Camille (CEA/DAM), Lalet Pierre (CEA/DAM)
and it is hereby released to the general public under the following terms:
Redistribution and use in source and binary forms, with or without modification,
are permitted.
================================================================================

The package contains:

+ README:
        This file.

+ kdcdump.patch:
        A patch for MIT Kerberos 5 kdb5_util tool. Run it on a KDC server as
root to export the realm database unencrypted.

+ kdcdump2john.py:
        Converts the output of the previous tool in a JohnTheRipper
understandable format.

+ john.krb5-18-23_fmt.patch:
        Provide the format "krb5-18" (Kerberos5 aes256-cts-hmac-sha1-96) and
"krb5-23" (arcfour-hmac) for JohnTheRipper software. Tested on 1.7.9-jumbo-6.

================================================================================

Example:

>kdb5_util.patched
...
test/admin@OLYMPE.OL
18,fc77e6ffc07b469ba90ad4a979bcbb64709177c74af7f8eceaada0cdc84c1117
23,1667b5ee168fc31fba85ffb8f925fb70
16,52d5670752073ee6644a578945ada45efd2cc149a1620ea4
...

>kdb5_util.patched > dump; python kdcdump2john.py dump;
...
test/admin@OLYMPE.OL:$krb18$OLYMPE.OLtestadmin$fc77e6ffc07b469ba90ad4a979bcbb647
09177c74af7f8eceaada0cdc84c1117
test/admin@OLYMPE.OL:$krb23$1667b5ee168fc31fba85ffb8f925fb70
...

>python kdcump2john.py dump > job; john job --format=krb5-23;
...
aqzsedrf	(test/admin@OLYMPE.OL)

================================================================================


Note:
        If the KDC server is not properly configured and provide the both
format, prefer the Arcfour-hmac format.

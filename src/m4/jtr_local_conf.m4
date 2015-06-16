# This file is Copyright (C) 2014 JimF
# and is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modifications, are permitted.
#
# This macro will create a john.local.conf, pre-seeding it with comments
# and all usable sections (with comment), turning them into skeleton
# 'Local:' sections.

AC_DEFUN([JTR_JOHN_LOCAL_CONF], [
   AC_MSG_CHECKING([for john.local.conf])
   AS_IF([test -e "../run/john.local.conf"],AC_MSG_RESULT([exists]),
		[AC_MSG_RESULT([not found])
		echo "configure: creating ../run/john.local.conf (with skeleton sections)"
		cat >../run/john.local.conf.tmp <<_EOF
# Within john.local.conf, we can add or fully overwrite any exiting section
# from any of the other .conf file. However if we add a special named
# section that is the same name as some other section, but with Local:
# appenneded, then this special section will allow the params from the
# original section in john.conf, to be modified.  Any param from that
# original section which is placed into this 'Local:' section will be
# updated, without having to edit the john.conf file. The john.conf file
# is a file owned by the JtR project.  It gets updated and edited by the
# JtR development team.  User hand edits to this file are lost when JtR
# updates. So it is recommended that updates to sections in that file are
# not done by editing the john.conf file, but by adding 'Local:' sections
# to this file, overriding parameters. NOTE, that a section starting out
# with 'List.' can not be modified with a 'Local:'. This is because
# there is no way to edit a List.  A List is used for things such as
# Rules, or External scripts.  Those sections can be replaced fully if
# put into this file, but can not be done with a 'Local:'
#
# This file was auto-created by the ./configure script when run. The
# ./configure added Local: sections for all non-list sections from the
# set of *.conf files present at the time ./configure was run. This will
# ONLY be done if this john.local.conf file does NOT exist. Once this
# file exists, it will not be updated again, by JtR code.

_EOF

		[grep "^\[.*\]$" ../run/john.conf | grep -v "List\." | grep -v "Local:" > ../run/john.local.conf.tmp2]
		# NOTE, had to use a quadragraphs for unbalanced openbracket characters, pound character, and dollar signs.
		[awk -F@<:@ '{printf("@%:@ Use this section used to override params in section @<:@%s\n@<:@Local:%s\n\n",@S|@2,@S|@2);}' < ../run/john.local.conf.tmp2 >> ../run/john.local.conf.tmp]
		rm ../run/john.local.conf.tmp2
		mv ../run/john.local.conf.tmp ../run/john.local.conf
		])
])

dnl This is the awk command (without ugly quadragraphs).  I could find no other way to make this work.
dnl awk -F[ '{printf("# Use this section used to override params in section [%s\n[Local:%s\n\n",$2,$2);}'
dnl
dnl and the final 'result' for [Option:MPI] section when run through the awk is:
dnl    # Use this section used to override params in section [Option:MPI]
dnl    [Local:Option:MPI]
dnl        --blank line--
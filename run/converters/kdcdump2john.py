#! /usr/bin/env python
#
# Kdcdump patch output translation for JtR
# August of 2012 by Mougey Camille
#
# This software is Copyright C 2012, Mougey Camille
# and it is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without modification,
# are permitted.

import sys


def usage():
    sys.stdout.write("""Usage: %s [dump]\n""" % sys.argv[0])

if (len(sys.argv) < 2):
    usage()
    exit()

dump_f = open(sys.argv[1], "r")
name = "unknown"
for l in dump_f.readlines():
    i = l.split(",")
    if (len(i) == 1):
        if (l.strip()):
            name = l.strip()
    if (i[0] == "23"):
        sys.stdout.write("%s:$krb23$%s\n" % (name, i[1].strip()))
    elif (i[0] == "18"):
        salt = name.split("@")[1] + name.split("@")[0].replace("/", "")
        sys.stdout.write("%s:$krb18$%s$%s\n" % (name, salt, i[1].strip()))

dump_f.close()

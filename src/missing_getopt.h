/* missing_getopt.h  (Original name XGetopt.h)
 *
 * Author:  Hans Dietrich
 *          hdietrich2@hotmail.com
 *
 * This software is released into the public domain.
 * You are free to use it in any way you like.
 *
 * This software is provided "as is" with no expressed
 * or implied warranty.  I accept no liability for any
 * damage or loss of business that this software may cause.
 *
 */

/*
 * This software was written by Hans Dietrich hdietrich2 at hotmail
 * dot com 2002, 2003. Source placed in public domain (original
 * statement above in this file).
 * This software was modified by JimF jfoug AT cox dot net
 * in 2014. No copyright is claimed, and all modifications to this source
 * fall under original public domain license statement.
 * In case this attempt to disclaim copyright and place the software in
 * the public domain is deemed null and void, then the software is
 * Copyright (c) 2002-3 Hans Dietrich / Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * getopt code for systems lacking them.
 *
 * Updated by JimF (2014).
 *   renamed to missing_getopt.[ch]
 *   some minor porting to 'C' from C++  (comments, vars at top of blocks, etc)
 *   Made optind start at 1, and use 1 as the 'reset' var (0 was being used).
 *   stripped TCHAR and msvc specific unicode stuff.
 *   return -1 not EOF
 *   modified the comments, removing a large 'usage' block.
 *   The other parts of the headers, including PD statement, were kept.
 */

#ifndef XGETOPT_H
#define XGETOPT_H

extern int optind, opterr;
extern char *optarg;

int getopt(int argc, char *argv[], char *optstring);

#endif //XGETOPT_H

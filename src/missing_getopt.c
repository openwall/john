/*
 * This software was written by Hans Dietrich hdietrich2 at hotmail
 * dot com 2002, 2003. Source placed in public domain (original
 * statement below in this file).
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

/*
 * XGetopt.cpp  Version 1.2
 *
 * Author:  Hans Dietrich
 *          hdietrich2@hotmail.com
 *
 * Description:
 *     XGetopt.cpp implements getopt(), a function to parse command lines.
 *
 * History
 *     Version 1.2 - 2003 May 17
 *     - Added Unicode support   (Removed this, JimF)
 *
 *     Version 1.1 - 2002 March 10
 *     - Added example to XGetopt.cpp module header (removed this, JimF)
 *
 * This software is released into the public domain.
 * You are free to use it in any way you like.
 *
 * This software is provided "as is" with no expressed
 * or implied warranty.  I accept no liability for any
 * damage or loss of business that this software may cause.
 */

#include <stdio.h>
#include <string.h>
#include "missing_getopt.h"

/*
 *
 *  X G e t o p t . c p p   (renamed missing_getopt.h)
 *
 *
 *  NAME
 *       getopt -- parse command line options
 *
 *  SYNOPSIS
 *       int getopt(int argc, char *argv[], char *optstring)
 *
 *       extern char *optarg;
 *       extern int optind;
 *
 *  DESCRIPTION
 *       The getopt() function parses the command line arguments. Its
 *       arguments argc and argv are the argument count and array as
 *       passed into the application on program invocation.  In the case
 *       of Visual C++ programs, argc and argv are available via the
 *       variables __argc and __argv (double underscores), respectively.
 *       getopt returns the next option letter in argv that matches a
 *       letter in optstring.  (Note:  Unicode programs should use
 *       __targv instead of __argv.  Also, all character and string
 *       literals should be enclosed in _T( ) ).
 *
 *       optstring is a string of recognized option letters;  if a letter
 *       is followed by a colon, the option is expected to have an argument
 *       that may or may not be separated from it by white space.  optarg
 *       is set to point to the start of the option argument on return from
 *       getopt.
 *
 *       Option letters may be combined, e.g., "-ab" is equivalent to
 *       "-a -b".  Option letters are case sensitive.
 *
 *       getopt places in the external variable optind the argv index
 *       of the next argument to be processed.  optind is initialized
 *       to 0 before the first call to getopt.
 *
 *       When all options have been processed (i.e., up to the first
 *       non-option argument), getopt returns -1, optarg will point
 *       to the argument, and optind will be set to the argv index of
 *       the argument.  If there are no non-option arguments, optarg
 *       will be set to NULL.
 *
 *       The special option "--" may be used to delimit the end of the
 *       options;  -1 will be returned, and "--" (and everything after it)
 *       will be skipped.
 *
 *  RETURN VALUE
 *       For option letters contained in the string optstring, getopt
 *       will return the option letter.  getopt returns a question mark (?)
 *       when it encounters an option letter not included in optstring.
 *       -1 is returned when processing is finished.
 *
 *  BUGS
 *       1)  Long options are not supported.
 *       2)  The GNU double-colon extension is not supported.
 *       3)  The environment variable POSIXLY_CORRECT is not supported.
 *       4)  The + syntax is not supported.
 *       5)  The automatic permutation of arguments is not supported.
 *       6)  return EOF and not -1  (Fixed by JimF to be -1)
 */

char	*optarg;		/* global argument pointer */
int		optind = 1; 	/* global argv index   (Fixed (JimF) now start from 1) */

int getopt(int argc, char *argv[], char *optstring)
{
	static char *next = NULL;
	char c, *cp;

	if (optind == 1)	/* fixed (JimF) now restart if set to 1 */
		next = NULL;

	optarg = NULL;

	if (next == NULL || *next == 0)
	{
		if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == 0)
		{
			optarg = NULL;
			if (optind < argc)
				optarg = argv[optind];
			return -1;
		}

		if (strcmp(argv[optind], "--") == 0)
		{
			optind++;
			optarg = NULL;
			if (optind < argc)
				optarg = argv[optind];
			return -1;
		}

		next = argv[optind];
		next++;		/* skip past -   */
		optind++;
	}

	c = *next++;
	cp = strchr(optstring, c);

	if (cp == NULL || c == ':')
		return '?';
	cp++;
	if (*cp == ':')
	{
		if (*next != 0)
		{
			optarg = next;
			next = NULL;
		}
		else if (optind < argc)
		{
			optarg = argv[optind];
			optind++;
		}
		else
			return '?';
	}
	return c;
}

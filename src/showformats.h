/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2000,2003,2005,2010-2012,2015-2019 by Solar Designer
 *
 * ...with heavy changes in the jumbo patch, by magnum and various authors
 */

#ifndef _JOHN_SHOWFORMATS_H
#define _JOHN_SHOWFORMATS_H

extern void showformats_skipped(const char *origin,
	char **login, char **ciphertext,
	struct db_options *db_opts, int line_no);

extern void showformats_regular(char **login, char **ciphertext,
	char **gecos, char **home, char **uid, char *source,
	struct db_options *db_opts, int line_no,
	char **fields, char *gid, char *shell,
	int huge_line);

#endif

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2005,2008,2013 by Solar Designer
 */

/*
 * Charset file generation.
 */

#ifndef _JOHN_CHARSET_H
#define _JOHN_CHARSET_H

#include "params.h"
#include "loader.h"

/*
 * While CHARSET_MIN and CHARSET_MAX are configurable in params.h, CHARSET_SIZE
 * is expected (by declarations and code in charset.c and inc.c) to be exactly
 * (CHARSET_MAX - CHARSET_MIN + 1).  So let's define it that way in here.
 */
#define CHARSET_SIZE			(CHARSET_MAX - CHARSET_MIN + 1)

/*
 * Charset file control char codes (only CHARSET_ESC is reserved, and can't
 * be used in a charset).
 */
#define CHARSET_ESC			0
#define CHARSET_NEW			1
#define CHARSET_LINE			2

/*
 * Charset file header.
 */
struct charset_header {
/* CHARSET_V* */
	char version[4];

/* A checksum of the file or equivalent plus some space for future extensions
 * (only 4 bytes are used currently) */
	unsigned char check[24];

/* CHARSET_MIN, CHARSET_MAX */
	unsigned char min, max;

/* CHARSET_LENGTH */
	unsigned char length;

/* Number of different characters, up to (max - min + 1) */
	unsigned char count;

/* File offsets for each length, 32-bit little endian */
	unsigned char offsets[CHARSET_LENGTH][4];

/*
 * Cracking order.
 *
 * This is a list of current {length, fixed index position, character count}.
 * There are CHARSET_LENGTH different lengths, and fixed index position is up
 * to the current length, which means that we have exactly (CHARSET_LENGTH *
 * (CHARSET_LENGTH + 1) / 2) different {length, fixed index position} pairs;
 * for each such pair we need to try all charsets from 1 character and up to
 * CHARSET_SIZE characters large.
 */
	unsigned char order
		[CHARSET_LENGTH * (CHARSET_LENGTH + 1) / 2 * CHARSET_SIZE * 3];
};

/*
 * Reads a charset file header.
 * Returns zero on success, non-zero on error.
 */
extern int charset_read_header(FILE *file, struct charset_header *header);

/*
 * Generates a charset file, based on plaintexts in the database.
 */
extern void do_makechars(struct db_main *db, char *charset);

#endif

/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2000 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Simple C compiler.
 */

#ifndef _JOHN_COMPILER_H
#define _JOHN_COMPILER_H

/*
 * Error codes.
 */
#define C_ERROR_NONE			0
#define C_ERROR_UNKNOWN			1
#define C_ERROR_UNEXPECTED		2
#define C_ERROR_COUNT			3
#define C_ERROR_TOOLONG			4
#define C_ERROR_TOOCOMPLEX		5
#define C_ERROR_ARRAYSIZE		6
#define C_ERROR_DATASIZE		7
#define C_ERROR_RANGE			8
#define C_ERROR_DUPE			9
#define C_ERROR_RESERVED		10
#define C_ERROR_NOTINFUNC		11
#define C_ERROR_NESTEDFUNC		12
#define C_ERROR_NOTINIF			13
#define C_ERROR_NOTINLOOP		14
#define C_ERROR_EOF			15
#define C_ERROR_INTERNAL		16

/*
 * Error names.
 */
extern char *c_errors[];

/*
 * Last error code.
 */
extern int c_errno;

/*
 * Data type used by compiled programs.
 */
typedef int c_int;

/*
 * Identifier list entry.
 */
struct c_ident {
/* Pointer to next entry */
	struct c_ident *next;

/* This identifier */
	char *name;

/* Its address */
	void *addr;
};

/*
 * Runs the compiler, and allocates some memory for its output and the
 * program's data. Returns one of the error codes.
 */
extern int c_compile(int (*ext_getchar)(void), void (*ext_rewind)(void),
	struct c_ident *externs);

/*
 * Returns the function's address or NULL if not found.
 */
extern void *c_lookup(char *name);

/*
 * Executes a function previously compiled with c_compile().
 */
#define c_execute(addr) \
	if (addr) \
		c_execute_fast(addr)
extern void c_execute_fast(void *addr);

#endif

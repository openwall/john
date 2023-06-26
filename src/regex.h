/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Regular expression cracker.
 */

#ifndef _JOHN_REGEX_H
#define _JOHN_REGEX_H

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBREXGEN || HAVE_REXGEN
#undef HAVE_REXGEN
#define HAVE_REXGEN 1
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#if defined(_WIN32)
/* librexgen fux this up for Win32 builds. We have coded JtR to use sprintf_s, and not _snprintf. They ARE different */
#undef  snprintf
#endif
#include <librexgen/c/librexgen.h>
#include <librexgen/c/iterator.h>
#if defined(_WIN32)
/* librexgen fux this up for Win32 builds. We have coded JtR to use sprintf_s, and not _snprintf. They ARE different */
#undef  snprintf
#define snprintf(str, size, ...) vc_fixed_snprintf((str), (size), __VA_ARGS__)
extern int vc_fixed_snprintf(char *Dest, size_t max_cnt, const char *Fmt, ...);
#endif

/* require at least version 2.1.5 of rexgen */
#if (JS_REGEX_MAJOR_VERSION > 2) || ((JS_REGEX_MAJOR_VERSION == 2) && ((JS_REGEX_MINOR_VERSION > 1) || (JS_REGEX_BUILD_VERSION >= 5)))

#include "loader.h"
/*
 * Runs the Regular expression cracker
 */
void do_regex_crack(struct db_main *db, const char *regex);
int do_regex_hybrid_crack(struct db_main *db, const char *regex,
                          const char *base_word, int bCase, const char *regex_alpha);
char *prepare_regex(char *regex, int *bCase, char **regex_alpha);
int rexgen_restore_state_hybrid(const char *sig, FILE *file);

#else
#undef HAVE_REXGEN
#define do_regex_hybrid_crack(a,word,b,c) crk_process_key(word)
#define prepare_regex(a,b,c)
#ifndef _MSC_VER
#warning Notice: rexgen cracking mode disabled, Library is installed, it is too old.
#warning         At least version 2.1.5 is required!
#endif
#endif
#else
#define do_regex_hybrid_crack(a,word,b,c) crk_process_key(word)
#define prepare_regex(a,b,c)
#endif

#endif

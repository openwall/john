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

#if HAVE_REXGEN
  #define UNICODE
  #define _UNICODE
  #include <librexgen/api/c/librexgen.h>

  #if (JS_REGEX_MAJOR_VERSION>1) || ((JS_REGEX_MAJOR_VERSION==1)&&(JS_REGEX_MINOR_VERSION>=1))

    #include "loader.h"
    /*
     * Runs the Regular expression cracker
     */
    void do_regex_crack(struct db_main *db, const char *regex);
    int do_regex_crack_as_rules(const char *regex, const char *base_word);

  #else
    #undef HAVE_REXGEN
    #define do_regex_crack_as_rules(a,word) crk_process_key(word)
	#ifndef _MSC_VER
	#warning Notice: rexgen cracking mode disabled, Library is installed, it is too old.
	#endif
  #endif
#else
  #define do_regex_crack_as_rules(a,word) crk_process_key(word)
#endif

#endif

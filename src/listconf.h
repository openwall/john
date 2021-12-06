/*
 * Copyright (c) 2012, 2013 Frank Dittrich and magnum
 *
 * This software is hereby released to the general public under the following
 * terms:  Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef _JOHN_LISTCONF_H
#define _JOHN_LISTCONF_H

#if HAVE_MPI
#ifdef _OPENMP
#define _MP_VERSION " MPI + OMP"
#else
#define _MP_VERSION " MPI"
#endif
#else
#ifdef _OPENMP
#define _MP_VERSION " OMP"
#else
#define _MP_VERSION ""
#endif
#endif

#ifdef DEBUG
#define DEBUG_STRING " debug"
#else
#define DEBUG_STRING ""
#endif

#ifdef WITH_ASAN
#define ASAN_STRING " ASan"
#else
#define ASAN_STRING ""
#endif

#ifdef WITH_UBSAN
#define UBSAN_STRING " UbSan"
#else
#define UBSAN_STRING ""
#endif

#if HAVE_OPENCL
#define OCL_STRING " OPENCL"
#else
#define OCL_STRING ""
#endif

#if HAVE_ZTEX
#define ZTEX_STRING " ZTEX"
#else
#define ZTEX_STRING ""
#endif

#define _STR_VALUE(arg)			#arg
#define STR_MACRO(n)			_STR_VALUE(n)

#if JTR_RELEASE_BUILD
#undef JTR_GIT_VERSION
#define JTR_GIT_VERSION JUMBO_VERSION
#endif

/* Suboptions that can be used before full initialization, like --list=help */
void listconf_parse_early(void);

/* Suboptions that depend on full initialization, like --list=externals */
void listconf_parse_late(void);

#endif

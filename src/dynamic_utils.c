/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2009-2012. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2009 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Generic MD5 hashes cracker
 *
 * Preloaded types dynamic_0 to dynamic_999 are 'reserved' types.
 * They are loaded from this file. If someone tryes to build a 'custom'
 * type in their john.ini file using one of those, john will abort
 * the run.
 *
 * Renamed and changed from dynamic* to dynamic*.  We handle MD5 and SHA1
 * at the present time.  More crypt types 'may' be added later.
 * Added SHA2 (SHA224, SHA256, SHA384, SHA512), GOST, Whirlpool crypt types.
 * Whirlpool use oSSSL if OPENSSL_VERSION_NUMBER >= 0x10000000, otherwise use sph_* code.
 */

#include <string.h>

#if AC_BUILT
#include "autoconfig.h"
#endif

#include "arch.h"

#if defined(SIMD_COEF_32) && !ARCH_LITTLE_ENDIAN
	#undef SIMD_COEF_32
	#undef SIMD_COEF_64
	#undef SIMD_PARA_MD5
	#undef SIMD_PARA_MD4
	#undef SIMD_PARA_SHA1
	#undef SIMD_PARA_SHA256
	#undef SIMD_PARA_SHA512
	#define BITS ARCH_BITS_STR
#endif

#if !FAST_FORMATS_OMP
#ifdef _OPENMP
  #define FORCE_THREAD_MD5_body
#endif
#undef _OPENMP
#endif

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "config.h"
#include "md5.h"
#include "dynamic.h"
#ifndef UNICODE_NO_OPTIONS
#include "options.h"
#endif

#ifndef DYNAMIC_DISABLED

void dynamic_DISPLAY_ALL_FORMATS()
{
	int i;
	for (i = 0; i < 1000; ++i)
	{
		char *sz = dynamic_PRELOAD_SIGNATURE(i);
		char Type[14], *cp;
		if (!sz)
			break;
		strnzcpy(Type, sz, sizeof(Type));
		cp = strchr(Type, ':');
		if (cp) *cp = 0;
		printf("Format = %s%s  type = %s\n", Type, strlen(Type)<10?" ":"", sz);
	}

	// The config has not been loaded, so we have to load it now, if we want to 'check'
	// and show any user set md5-generic functions.
#if JOHN_SYSTEMWIDE
	cfg_init(CFG_PRIVATE_FULL_NAME, 1);
#endif
	cfg_init(CFG_FULL_NAME, 1);

	for (i = 1000; i < 10000; ++i)
	{
		char *sz = dynamic_LOAD_PARSER_SIGNATURE(i);
		if (sz && dynamic_IS_VALID(i, 0) == 1)
			printf("UserFormat = dynamic_%d  type = %s\n", i, sz);
	}
}

// Only called at load time, so does not have to be overly optimal
static int ishexdigit(char c) {
	if (c >= '0' && c <= '9')
		return 1;
	if (c >= 'a' && c <= 'f')
		return 1;
	if (c >= 'A' && c <= 'F')
		return 1;
	return 0;
}
// Only called at load time, so does not have to be overly optimal
char *dynamic_Demangle(char *Line, int *Len)
{
	char *tmp, *cp, *cp2, digits[3];
	if (!Line || !strlen(Line)) {
		if (Len) *Len = 0;
		return str_alloc_copy("");
	}
	tmp = str_alloc_copy(Line);
	cp = tmp;
	cp2 = Line;
	while (*cp2)
	{
		if (*cp2 != '\\')
			*cp++ = *cp2++;
		else
		{
			++cp2;
			if (*cp2 == '\\')
				*cp++ = *cp2++;
			else
			{
				unsigned val;
				if (*cp2 != 'x') {
					*cp++ = '\\';
					continue;
				}
				++cp2;
				if (!cp2[0]) {
					*cp++ = '\\';
					*cp++ = 'x';
					continue;
				}
				digits[0] = *cp2++;
				if (!cp2[0] || !ishexdigit(digits[0])) {
					*cp++ = '\\';
					*cp++ = 'x';
					*cp++ = digits[0];
					continue;
				}
				digits[1] = *cp2++;
				if (!ishexdigit(digits[1])) {
					*cp++ = '\\';
					*cp++ = 'x';
					*cp++ = digits[0];
					*cp++ = digits[1];
					continue;
				}
				digits[2] = 0;
				val = (unsigned)strtol(digits, NULL, 16);
				sprintf(cp, "%c", val);
				++cp;
			}
		}
	}
	*cp = 0;
	if (Len) *Len = cp-tmp;
	return tmp;
}

#endif /* DYNAMIC_DISABLED */

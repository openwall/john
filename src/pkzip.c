#include "arch.h"
#include <stdio.h>
#include <string.h>
#include "misc.h"
#include "common.h"
#include "memory.h"
#include "formats.h"
#include "pkzip.h"
#include "memdbg.h"

/* helper functions for reading binary data of known little endian */
/* format from a file. Works whether BE or LE system.              */
u32 fget32LE(FILE * fp)
{
	u32 v = fgetc(fp);
	v |= fgetc(fp) << 8;
	v |= fgetc(fp) << 16;
	v |= fgetc(fp) << 24;
	return v;
}

u16 fget16LE(FILE * fp)
{
	u16 v = fgetc(fp);
	v |= fgetc(fp) << 8;
	return v;
}

/* Similar to strtok, but written specifically for the format. */
u8 *pkz_GetFld(u8 *p, u8 **pRet) {
	if (!p) {
		*pRet = (u8*)"";
		return NULL;
	}
	*pRet = p;
	if (*p==0)
		return NULL;
	if (*p == '*') {
		*p = 0;
		return ++p;
	}
	while (*p && *p != '*')
		++p;
	if (*p)
	  *p++ = 0;
	return p;
}

int pkz_is_hex_str(const u8 *cp) {
	int len, i;

	if (!cp || !*cp)
		return 0; /* empty is NOT 'fine' */
	len = strlen((c8*)cp);
	for (i = 0; i < len; ++i) {
		if (atoi16[ARCH_INDEX(cp[i])] == 0x7F ||
		    (cp[i] >= 'A' && cp[i] <= 'F')) /* support lowercase only */
			return 0;
	}
	return 1;
}

unsigned pkz_get_hex_num(const u8 *cp) {
	char b[3];
	unsigned u;
	b[0] = (c8)cp[0];
	b[1] = (c8)cp[1];
	b[2] = 0;
	sscanf(b, "%x", &u);
	return u;
}

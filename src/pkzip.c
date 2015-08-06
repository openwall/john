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

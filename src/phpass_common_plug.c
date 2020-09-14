/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2016 JimF
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 *  Functions and data which is common among the phpass-md5 crackers
 *  (CPU, OpenCL)
 */

#include <stdio.h>

#include "formats.h"
#include "memory.h"
#include "common.h"
#include "phpass_common.h"

struct fmt_tests phpass_common_tests[] = {
	{"$P$900000000m6YEJzWtTmNBBL4jypbHv1", "openwall"},
	{"$P$90000000000tbNYOc9TwXvLEI62rPt1", ""},
	{"$P$9saltstriAcRMGl.91RgbAD6WSq64z.", "a"},
	{"$P$9saltstriMljTzvdluiefEfDeGGQEl/", "ab"},
	{"$P$900000000jPBDh/JWJIyrF0.DmP7kT.", "ala"},
	{"$P$9sadli2.wzQIuzsR2nYVhUSlHNKgG/0", "john"},
	{"$P$9saltstri3JPgLni16rBZtI03oeqT.0", "abcde"},
	{"$P$900000000zgzuX4Dc2091D8kak8RdR0", "h3ll00"},
	{"$P$9saltstriXeNc.xV8N.K9cTs/XEn13.", "abcdefg"},
	{"$H$9saltstriSUQTD.yC2WigjF8RU0Q.Z.", "abcdefghi"},
	{"$P$900112200B9LMtPy2FSq910c1a6BrH0", "1234567890"},
	{"$P$9RjH.g0cuFtd6TnI/A5MRR90TXPc43/", "password__1"},
	{"$P$9saltstriGLUwnE6bl91BPJP6sxyka.", "abcdefghijkl"},
	{"$P$9saltstriq7s97e2m7dXnTEx2mtPzx.", "abcdefghijklm"},
	{"$P$9saltstriTWMzWKsEeiE7CKOVVU.rS0", "abcdefghijklmn"},
	{"$P$9saltstriXt7EDPKtkyRVOqcqEW5UU.", "abcdefghijklmno"},
	{"$H$9aaaaaSXBjgypwqm.JsMssPLiS8YQ00", "test1"},
	{"$H$9PE8jEklgZhgLmZl5.HYJAzfGCQtzi1", "123456"},
	{"$H$9pdx7dbOW3Nnt32sikrjAxYFjX8XoK1", "123456"},
	{"$P$912345678LIjjb6PhecupozNBmDndU0", "thisisalongertestPW"},
	{"$H$9A5she.OeEiU583vYsRXZ5m2XIpI68/", "123456"},
	{"$P$917UOZtDi6ksoFt.y2wUYvgUI6ZXIK/", "test1"},
	{"$P$91234567AQwVI09JXzrV1hEC6MSQ8I0", "thisisalongertest"},
	{"$P$9234560A8hN6sXs5ir0NfozijdqT6f0", "test2"},
	{"$P$9234560A86ySwM77n2VA/Ey35fwkfP0", "test3"},
	{"$P$9234560A8RZBZDBzO5ygETHXeUZX5b1", "test4"},
	{"$P$91234567xogA.H64Lkk8Cx8vlWBVzH0", "thisisalongertst"},
	{"$P$612345678si5M0DDyPpmRCmcltU/YW/", "JohnRipper"}, // note smaller loop count
	{"$H$712345678WhEyvy1YWzT4647jzeOmo0", "JohnRipper"}, // note smaller loop count (phpbb w/older PHP version)
	{"$P$B12345678L6Lpt4BxNotVIMILOa9u81", "JohnRipper"}, // note larger loop count  (Wordpress)
	{"$P$/$elftestvZI8qryAvItDDipNbgRpu0", "123"},
	{"$P$/$elftestfBLqkB7/Z7m9Yp5lKz8Yl0", "1234"},
	{"$P$/$elftestcDe.VEWyDmgcrJ5uj8K561", "1234567"},
	{"$P$/$elftestCH99Hx5wlUMsESqM4R1JA0", "12345678"},
	{"$P$/$elftestTAOkx4egOt8dB96ENOl0n/", "12345678901"},
	{"$P$/$elftest5JGnE8Ps0hGzQT9Mj387A0", "123456789012"},
	{"$P$/$elftestWsJ7oCHvCfLkMtavnwI8b0", "123456789012345"},
	{"$P$/$elftesteH9rZoTgvlMUz/SERywJj0", "1234567890123456"},
	{"$P$/$elftest6h05401ID1h0Gw6mINOrx0", "1234567890123456789"},
	{"$P$/$elftestaF7We2XuR74GBSOJTZz7y1", "12345678901234567890"},
	{"$P$/$elftest9NZF/EHtO5V/2GAx28gP8/", "12345678901234567890123"},
	{"$P$/$elftest9GkE8K.SjwYriMO3q0KEX/", "123456789012345678901234"},
	{"$P$/$elftest7nXdApFzJV2dRoDJ1qP7d1", "123456789012345678901234567"},
	{"$P$/$elftestszixMZ3o93mWfA5cLJb0P1", "1234567890123456789012345678"},
	{"$P$/$elftestwwTEf92H/S0Msic99nSlh.", "1234567890123456789012345678901"},
	{"$P$/$elftestiV.fzEfcYzDEh.ixp3O481", "12345678901234567890123456789012"},
	{"$P$/$elftesthbTugsGHExTF3KmFAS4BI/", "12345678901234567890123456789012345"},
	{"$P$/$elftest.HlNNFK/NoHamyLQNvlgH/", "123456789012345678901234567890123456"},
	{"$P$/$elftest4SM/5aiJcCzhaUptVWBUH/", "123456789012345678901234567890123456789"},
//	{"$P$/$elftestSCOanM8VQmeR1zlLWq3Rr1", "1234567890123456789012345678901234567890"},
	{NULL}
};

int phpass_common_valid(char *ciphertext, struct fmt_main *self)
{
	int i;
	unsigned count_log2;

	if (ciphertext[0] != '$')
		return 0;
	// Handle both the phpass signature, and the phpBB v3 signature (same formula)
	// NOTE we are only dealing with the "portable" hashes
	if (ciphertext[1] != 'P' && ciphertext[1] != 'H')
		return 0;
	if (ciphertext[2] != '$')
		return 0;
	if (strnlen(ciphertext, CIPHERTEXT_LENGTH + 1) != CIPHERTEXT_LENGTH)
		return 0;

	if (self_test_running && !strncmp(ciphertext, "$P$/$elftest", 12))
		return 1;

	for (i = FORMAT_TAG_LEN; i < CIPHERTEXT_LENGTH; ++i)
		if (atoi64[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;

	count_log2 = atoi64[ARCH_INDEX(ciphertext[FORMAT_TAG_LEN])];
	if (count_log2 < 7 || count_log2 > 31)
		return 0;

	return 1;
}

void *phpass_common_binary(char *ciphertext)
{
	int i;
	unsigned sixbits;
	static unsigned char *b=0;
	int bidx=0;
	char *pos;

	if (!b) b = mem_alloc_tiny(16,4);
	pos = &ciphertext[FORMAT_TAG_LEN+1+8];
	for (i = 0; i < 5; ++i)
	{
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits<<6);
		sixbits >>= 2;
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits<<4);
		sixbits >>= 4;
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits<<2);
	}
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	b[bidx] = sixbits;
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	b[bidx] |= (sixbits<<6);
#if !ARCH_LITTLE_ENDIAN && defined (SIMD_COEF_32)
	alter_endianity(b, 16);
#endif
	return b;
}

// convert dynamic_17 back into phpass format
char *phpass_common_split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];
	char *cpH, *cpS;

	if (strncmp(ciphertext, FORMAT_TAG3, FORMAT_TAG3_LEN))
		return ciphertext;
	cpH = ciphertext + FORMAT_TAG3_LEN;
	strcpy(out, FORMAT_TAG);
	cpS = strchr(cpH, '$');
	if (!cpS)
		return ciphertext;
	++cpS;
	out[3] = cpS[8];
	memcpy(&out[4], cpS, 8);
	memcpy(&out[12], cpH, 22);
	return out;
}

char *phpass_common_prepare(char *split_fields[10], struct fmt_main *self)
{
	return phpass_common_split(split_fields[1], 0, self);
}

unsigned int phpass_common_iteration_count(void *salt)
{
	return 1U<<atoi64[(((unsigned char*)salt)[8])];
}

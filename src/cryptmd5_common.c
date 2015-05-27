/* 
 * cryptmd5 cracker patch for JtR, common code. 2014 by JimF
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location
 */
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "cryptmd5_common.h"
#include "memdbg.h"

int cryptmd5_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *pos, *start;

	if (strncmp(ciphertext, md5_salt_prefix, sizeof(md5_salt_prefix)-1)) {
		if (strncmp(ciphertext, apr1_salt_prefix, sizeof(apr1_salt_prefix)-1) &&
		    strncmp(ciphertext, smd5_salt_prefix, sizeof(smd5_salt_prefix)-1))
			return 0;
		ciphertext += 3;
	}

	for (pos = &ciphertext[3]; *pos && *pos != '$'; pos++);
	if (!*pos || pos < &ciphertext[3] || pos > &ciphertext[11]) return 0;

	start = ++pos;
	while (atoi64[ARCH_INDEX(*pos)] != 0x7F) pos++;
	if (*pos || pos - start != 22) return 0;

	if (atoi64[ARCH_INDEX(*(pos - 1))] & 0x3C) return 0;

	return 1;
}

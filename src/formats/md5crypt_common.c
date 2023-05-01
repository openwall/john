/*
 * cryptmd5 cracker patch for JtR, common code. 2014 by JimF
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location
 */
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5crypt_common.h"

int cryptmd5_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *pos, *start;

	if (!strncmp(ciphertext, md5_salt_prefix, md5_salt_prefix_len))
		ciphertext += md5_salt_prefix_len;
	else if (!strncmp(ciphertext, apr1_salt_prefix, apr1_salt_prefix_len))
		ciphertext += apr1_salt_prefix_len;
	else if (!strncmp(ciphertext, smd5_salt_prefix, smd5_salt_prefix_len))
		ciphertext += smd5_salt_prefix_len;
	else
		return 0;

	for (pos = ciphertext; *pos && *pos != '$'; pos++);
	if (!*pos || pos < ciphertext || pos > &ciphertext[11]) return 0;

	start = ++pos;
	while (atoi64[ARCH_INDEX(*pos)] != 0x7F) pos++;
	if (*pos || pos - start != 22) return 0;

	if (atoi64[ARCH_INDEX(*(pos - 1))] & 0x3C) return 0;

	return 1;
}

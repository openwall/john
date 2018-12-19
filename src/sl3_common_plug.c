/*
 * Copyright (c) 2017 magnum.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "formats.h"
#include "memory.h"
#include "base64_convert.h"
#include "sl3_common.h"

struct fmt_tests sl3_tests[] = {
	{"$sl3$35831503698405$d8f6b336a4df3336bf7de58a38b1189f6c5ce1e8", "621888462499899"},
	{"", "123456789012345", {"112233445566778", "545fabcb0af7d923a56431c9131bfa644c408b47"}},
	{NULL}
};

/*
 * prepare() will put login field as a hex salt in the internal format of
 * $sl3$<imei>$<hash> and any 15th digit of the IMEI will be gone at that point
 * if it was ever present.
 */
char *sl3_prepare(char *split_fields[10], struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];
	int i, len;

	if (strlen(split_fields[1]) != 2 * BINARY_SIZE)
		return split_fields[1];

	if (!split_fields[0])
		return split_fields[1];

	len = strlen(split_fields[0]);

	if (len < 14 || len > 15)
		return split_fields[1];

	sprintf(out, "%s", SL3_MAGIC);

	for (i = 0; i < 14; i++) {
		if (split_fields[0][i] < '0' || split_fields[0][i] > '9')
			return split_fields[1];
		out[SL3_MAGIC_LENGTH + i] = split_fields[0][i];
	}

	out[SL3_MAGIC_LENGTH + i] = '$';

	for (i = 0; i < 2 * BINARY_SIZE; i++)
		out[SL3_MAGIC_LENGTH + 14 + 1 + i] = split_fields[1][i];

	out[SL3_MAGIC_LENGTH + 14 + 1 + i] = 0;

	return out;
}

/*
 * At this point in the flow we only accept the internal format of
 * "$sl3$<imei>$<hash>".  Only lower-case hex is allowed.
 */
int sl3_valid(char *ciphertext, struct fmt_main *self)
{
	int i;

	if (strncmp(ciphertext, SL3_MAGIC, SL3_MAGIC_LENGTH))
		return 0;
	ciphertext += SL3_MAGIC_LENGTH;

	for (i = 0; i < 14; i++)
		if (ciphertext[i] < '0' || ciphertext[i] > '9')
			return 0;
	ciphertext += 14;
	if (*ciphertext++ != '$')
		return 0;
	for (i = 0; i < 2 * BINARY_SIZE; i++)
		if (!((ciphertext[i] >= '0' && ciphertext[i] <= '9') ||
		      (ciphertext[i] >= 'a' && ciphertext[i] <= 'f')))
			return 0;
	return 1;
}

/* get_salt() adds the surrounding nulls. */
void *sl3_get_salt(char *ciphertext)
{
       static char *out;

       if (!out)
               out = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);

       ciphertext += SL3_MAGIC_LENGTH;
       memset(out, 0, SALT_SIZE);

       base64_convert(ciphertext, e_b64_hex, 14, out + 1,
                      e_b64_raw, 7, 0, 0);

       return out;
}

int sl3_salt_hash(void *salt)
{
	return *(unsigned int*)salt & (SALT_HASH_SIZE - 1);
}

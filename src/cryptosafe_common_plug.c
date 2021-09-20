/*
 * This software is Copyright (c) 2021, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "formats.h"
#include "memory.h"
#include "base64_convert.h"
#include "cryptosafe_common.h"

struct fmt_tests cryptosafe_tests[] = {
	{"$cryptosafe$1$RJ+YWtuyOoLnnOpOdmj43+hwO5cquMsSO3f/OiQfINofM+c0JVbIyUTQg3St+1Ue09QiZKlNnCAmlPHq2wuI31QoZQ/KNKZT/VMLd3qYbkOv873HT4wsYeavSwOqrdVdxpEimkqgdDkGP7XHfeFUCv6+jXFZioiR8jYrgxA8fDQQ5C+YReuvfiqLGaVrC9ih58X8Q7NLxAlQTGSQvHgsZI6DNfAsXw3Zt++fIJh9bdLzHDEBF/pLp47zj132UOYr6TuufnnA+HeUISdk+xH6/w==", "foobar"},
	{"2bImHcM6Pvcact+5JEFJXvJoNcRGBb4J8ymMd4q47lXzImgk/bofKCVdIV6XKctqBIzqo1dHqqZ9vZ4oT41d0PMszRAj1gvcayZB0Xy526KfAKTznqjSiKpgdq9xmWkHy+rECMwlMCm566tFM/4duBeRZy1nGUwxWnZCwcAvjmP00lS6/MQwU07z8luHKI9D", "magnum"},
	{NULL}
};

int cryptosafe_valid(char *ciphertext, struct fmt_main *self)
{
	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		ciphertext += FORMAT_TAG_LEN;

	if (base64_valid_length(ciphertext, e_b64_mime, flg_Base64_MIME_TRAIL_EQ_CNT, 0) != strlen(ciphertext))
		return 0;

	int len = B64_TO_RAW_LEN(base64_valid_length(ciphertext, e_b64_mime, flg_Base64_NO_FLAGS, 0));

	if (len % 16 || len < 32)
		return 0;

	return 1;
}

char *cryptosafe_split(char *ciphertext, int index, struct fmt_main *self)
{
	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return ciphertext;

	char *out = mem_alloc_tiny(strlen(ciphertext) + FORMAT_TAG_LEN + 1, MEM_ALIGN_NONE);

	sprintf(out, "%s%s", FORMAT_TAG, ciphertext);

	return out;
}

void *cryptosafe_get_salt(char *ciphertext)
{
	static struct custom_salt cs;

	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		ciphertext += FORMAT_TAG_LEN;

	int len = B64_TO_RAW_LEN(base64_valid_length(ciphertext, e_b64_mime, flg_Base64_NO_FLAGS, 0));
	char *blob = mem_alloc(len + 1);

	base64_convert(ciphertext, e_b64_mime, strlen(ciphertext),
	               blob, e_b64_raw, len, flg_Base64_NO_FLAGS, 0);

	memcpy(cs.ciphertext, blob, 16);

	MEM_FREE(blob);

	return (void *)&cs;
}

/*
 * Common code for the SolarWinds Orion format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "base64_convert.h"
#include "solarwinds_common.h"

#define HASH_LENGTH 88

struct fmt_tests solarwinds_tests[] = {
        {"$solarwinds$0$admin$/+PA4Zck3arkLA7iwWIugnAEoq4ocRsYjF7lzgQWvJc+pepPz2a5z/L1Pz3c366Y/CasJIa7enKFDPJCWNiKRg==", ""},
        {"$solarwinds$0$admin$5BqFpldsj5H9nbkkLjB+Cdi7WCXiUp5zBpO9Xs7/MKnnQAI0IE9gH+58LlS7/+a/7x1wWScI2iCGEtukgTiNeA==", "letmein"},
        {NULL}
};

int solarwinds_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* version */
		goto err;
	if (atoi(p) != 0)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* username */
		goto err;
	if (strlen(p) > 64)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* hash */
		goto err;

	if (strlen(p)-2 != base64_valid_length(p,e_b64_mime,flg_Base64_MIME_TRAIL_EQ, 0) || strlen(p)-1 > HASH_LENGTH-1)
                goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *solarwinds_get_binary(char *ciphertext)
{
        static union {
                unsigned char c[BINARY_SIZE];
                uint32_t dummy;
        } buf;
        unsigned char *out = buf.c;
        char *p;

	memset(buf.c, 0, BINARY_SIZE);

        p = strrchr(ciphertext, '$') + 1;
        base64_convert(p, e_b64_mime, strlen(p), (char*)out, e_b64_raw, sizeof(buf.c), flg_Base64_DONOT_NULL_TERMINATE, 0);

        return out;
}

void *solarwinds_get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;

	memset(&cs, 0, sizeof(cs));

	ctcopy += FORMAT_TAG_LEN;
        p = strtokm(ctcopy, "$");
        p = strtokm(NULL, "$");

	strncpy(cs.salt, p, 8);

	if (strlen(p) < 8)
		strncat(cs.salt, SALT_PADDING, 8 - strlen(cs.salt));

	MEM_FREE(keeptr);
	return (void *)&cs;
}

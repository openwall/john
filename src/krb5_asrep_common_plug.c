/*
 * Common code for the krb5asrep format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include <ctype.h>

#include "formats.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "krb5_asrep_common.h"

char *krb5_asrep_split(char *ciphertext, int index, struct fmt_main *self)
{
	static char *ptr, *keeptr;
	unsigned char etype = 0;
	char *p = ciphertext;
	int i;

	if (strnlen(ciphertext, LINE_BUFFER_SIZE) < LINE_BUFFER_SIZE &&
	    strstr(ciphertext, "$SOURCE_HASH$"))
		return ciphertext;

	ptr = mem_alloc_tiny(strlen(ciphertext) + FORMAT_TAG_LEN + ETYPE_TAG_LEN + 1, MEM_ALIGN_NONE);
	keeptr = ptr;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0) { // old format hashes
		memcpy(ptr, FORMAT_TAG, FORMAT_TAG_LEN);
		ptr += FORMAT_TAG_LEN;
		memcpy(ptr, "23$", ETYPE_TAG_LEN); // old hashes
		ptr += ETYPE_TAG_LEN;
		for (i = 0; i < strlen(ciphertext) + 1; i++)
			ptr[i] = tolower(ARCH_INDEX(ciphertext[i]));
	} else { // new format hashes (with FORMAT_TAG)
		p = ciphertext + FORMAT_TAG_LEN;
		if (!strncmp(p, "23$", ETYPE_TAG_LEN))
			etype = 23;
		else if (!strncmp(p, "17$", ETYPE_TAG_LEN))
			etype = 17;
		else if (!strncmp(p, "18$", ETYPE_TAG_LEN))
			etype = 18;
		if (etype != 23) {
			// skip over salt
			p = strchr(ciphertext + FORMAT_TAG_LEN + ETYPE_TAG_LEN + 1, '$') + 1;
			for (i = 0; i < p - ciphertext; i++)
				ptr[i] = ARCH_INDEX(ciphertext[i]);
			for (; i < strlen(ciphertext) + 1; i++)
				ptr[i] = tolower(ARCH_INDEX(ciphertext[i]));

		} else {
			for (i = 0; i < strlen(ciphertext) + 1; i++)
				ptr[i] = tolower(ARCH_INDEX(ciphertext[i]));
		}
	}

	return keeptr;
}

int krb5_asrep_valid(char *ciphertext, struct fmt_main *self, int is_cpu_format)
{
	char *p;
	char *ctcopy;
	char *keeptr;
	int extra;
	int len;
	unsigned char etype = 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) == 0) {
                ctcopy += FORMAT_TAG_LEN;
		/* determine etype */
		if (!strncmp(ctcopy, "23$", ETYPE_TAG_LEN))
			etype = 23;
		else if (!strncmp(ctcopy, "17$", ETYPE_TAG_LEN))
			etype = 17;
		else if (!strncmp(ctcopy, "18$", ETYPE_TAG_LEN))
			etype = 18;
		else
			goto err;
		ctcopy += ETYPE_TAG_LEN;
	}

	if (etype == 17 || etype == 18) {
		if (((p = strtokm(ctcopy, "$")) == NULL) || strlen(p) > 256) // salt
			goto err;
		if (((p = strtokm(NULL, "$")) == NULL))
			goto err;
		len = hexlen(p, &extra);
		if (!ishex(p) || len < (64 + 16) || len > (4092 * 2) || extra) // encrypted data
			goto err;
		if (((p = strtokm(NULL, "$")) == NULL))
			goto err;
		if (!ishex(p) || (hexlen(p, &extra) != 12 * 2 || extra)) // checksum
			goto err;
		MEM_FREE(keeptr);
		return 1;
	}

	if (!is_cpu_format && etype == 23)  // hack
		goto err;

	/* assume checksum */
	if (((p = strtokm(ctcopy, "$")) == NULL) || strlen(p) != 32)
		goto err;

	/* assume edata2 following */
	if (((p = strtokm(NULL, "$")) == NULL))
		goto err;
	if (!ishex(p) || (hexlen(p, &extra) < (64 + 16) || extra))
		goto err;

	if ((strtokm(NULL, "$") != NULL))
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *krb5_asrep_get_salt(char *ciphertext)
{
	int i;
	static struct custom_salt cs;

	char *p;
	char *ctcopy;
	char *keeptr;
	static void *ptr;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	memset(&cs, 0, sizeof(cs));
	cs.edata2 = NULL;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) == 0) {
		ctcopy += FORMAT_TAG_LEN;
		if (!strncmp(ctcopy, "23$", ETYPE_TAG_LEN))
			cs.etype = 23;
		else if (!strncmp(ctcopy, "17$", ETYPE_TAG_LEN))
			cs.etype = 17;
		else if (!strncmp(ctcopy, "18$", ETYPE_TAG_LEN))
			cs.etype = 18;
		ctcopy += ETYPE_TAG_LEN;

	} else {
		cs.etype = 23;
	}

	if (cs.etype == 17 || cs.etype == 18) {
		// salt
		p = strtokm(ctcopy, "$");
		strncpy(cs.salt, p, sizeof(cs.salt) - 1);
		cs.salt[sizeof(cs.salt) - 1] = 0;

		// encrypted data
		p = strtokm(NULL, "$");
		cs.edata2len = strlen(p) / 2;
		cs.edata2 = (unsigned char*)mem_calloc_tiny(cs.edata2len + 1, sizeof(char));
		for (i = 0; i < cs.edata2len; i++) { /* assume edata2 */
			cs.edata2[i] =
				atoi16[ARCH_INDEX(p[i * 2])] * 16 +
				atoi16[ARCH_INDEX(p[i * 2 + 1])];
		}

		// checksum
		p = strtokm(NULL, "$");
		for (i = 0; i < 12; i++) {
			cs.edata1[i] =
				atoi16[ARCH_INDEX(p[i * 2])] * 16 +
				atoi16[ARCH_INDEX(p[i * 2 + 1])];
		}
	} else if (((p = strtokm(ctcopy, "$")) != NULL) && strlen(p) == 32) { /* assume checksum */
		for (i = 0; i < 16; i++) {
			cs.edata1[i] =
				atoi16[ARCH_INDEX(p[i * 2])] * 16 +
				atoi16[ARCH_INDEX(p[i * 2 + 1])];
		}

		/* skip '$' */
		p += strlen(p) + 1;

		/* retrieve non-constant length of edata2 */
		cs.edata2len = strlen(p) / 2;
		cs.edata2 = (unsigned char*)mem_calloc_tiny(cs.edata2len + 1, sizeof(char));
		for (i = 0; i < cs.edata2len; i++) { /* assume edata2 */
			cs.edata2[i] =
				atoi16[ARCH_INDEX(p[i * 2])] * 16 +
				atoi16[ARCH_INDEX(p[i * 2 + 1])];
		}
	}

	MEM_FREE(keeptr);

	/* following is used to fool dyna_salt stuff */
	cs.dsalt.salt_cmp_offset = SALT_CMP_OFF(struct custom_salt, edata1);
	cs.dsalt.salt_cmp_size = SALT_CMP_SIZE(struct custom_salt, edata1, edata2len, 0);
	cs.dsalt.salt_alloc_needs_free = 0;

	ptr = mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	memcpy(ptr, &cs, sizeof(struct custom_salt));

	return (void *) &ptr;
}

unsigned int krb5_asrep_etype(void *salt)
{
	return (*(struct custom_salt**)salt)->etype;
}

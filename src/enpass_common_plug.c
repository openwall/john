/*
 * Common code for the Enpass Password Manager format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "enpass_common.h"
#include "memdbg.h"

int enpass_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int extra;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* version */
		goto err;
	if (atoi(p) != 0)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* iterations */
		goto err;
	if (atoi(p) != 24000)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* salt + data */
		goto err;
	if (hexlenl(p, &extra) != 2048 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *enpass_common_get_salt(char *ciphertext)
{
	int i;
	char *p = ciphertext;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));

	p = ciphertext + FORMAT_TAG_LEN;
	p = strchr(p, '$') + 1;
	cs.iterations = atoi(p);  // is this really OK?
	cs.salt_length = 16; // fixed

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < 16; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	for (; i < 1024; i++)
		cs.data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];

	return (void *)&cs;
}

/* Verify validity of page, see "lockBtree" function in SQLCipher */
int enpass_common_verify_page(unsigned char *page1)
{
	uint32_t pageSize;
	uint32_t usableSize;

	/* if (memcmp(page1, SQLITE_FILE_HEADER, 16) != 0) {
		return -1;
	} */

	if (page1[19] > 2) {
		return -1;
	}

	if (memcmp(&page1[21], "\100\040\040", 3) != 0) {
		return -1;
	}

	pageSize = (page1[16] << 8) | (page1[17] << 16);
	if (((pageSize - 1) & pageSize) != 0 || pageSize > SQLITE_MAX_PAGE_SIZE || pageSize <= 256) {
		return -1;
	}

	if ((pageSize & 7) != 0) {
		return -1;
	}
	usableSize = pageSize - page1[20];

	if (usableSize < 480) {
		return -1;
	}

	return 0; // success!
}

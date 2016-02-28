/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2016 JimF
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 *  Functions and data which is common among the pbkdf2_hmac_* crackers
 *  (CPU, OpenCL)
 */

#include <stdio.h>
#include "formats.h"
#include "memory.h"
#include "common.h"
#include "pbkdf2_hmac_common.h"
#define OPENCL_FORMAT
#define PBKDF2_HMAC_MD4_ALSO_INCLUDE_CTX 1
#include "pbkdf2_hmac_md4.h"
#define PBKDF2_HMAC_MD5_ALSO_INCLUDE_CTX 1
#include "pbkdf2_hmac_md5.h"

/*
 * Common stuff for pbkdf2-md4 hashes
 */

struct fmt_tests pbkdf2_hmac_md4_common_tests[] = {
	{"$pbkdf2-hmac-md4$1000$6d61676e756d$32ebfcea201e61cc498948916a213459", "magnum"},
	{"$pbkdf2-hmac-md4$1000$6d61676e756d$32ebfcea201e61cc498948916a213459c259c7b0a8ce9473368665f0808dcde1", "magnum"},
	{"$pbkdf2-hmac-md4$1$73616c74$1857f69412150bca4542581d0f9e7fd1", "password"},
	{"$pbkdf2-hmac-md4$10000$6d61676e756d$72afea482e97ffbba4171f5cc251215e", "Borkum"},
	{"$pbkdf2-hmac-md4$10000$6d61676e756d$2a945628a540f074a99a47cba86081b7", "Riff"},
	{"$pbkdf2-hmac-md4$1000$303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930$644e820a6c0cedb02f5d77cbb69c00a2", "magnum"},
	{"$pbkdf2-hmac-md4$1000$30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031$3d13e7c223ec854361499a5a8bf4adc9", "magnum"},
	{"$pbkdf2-hmac-md4$1000$3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132$e55d8efe6a2b7db90c5648fb17d063b4", "magnum"},
	{"$pbkdf2-hmac-md4$1000$303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233$18792d779ac2a8187d7fa656d792dc59", "magnum"},
	{"$pbkdf2-hmac-md4$1000$30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334$5442cc2bed8094d74e2a8b121362e802", "magnum"},
	{"$pbkdf2-hmac-md4$1000$303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839$21f2c2e53f44d3cefacaed6e0a299e82", "magnum"},
	{"$pbkdf2-hmac-md4$1000$30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930$9099d60b89319c9c817d9cd85bf208e0", "magnum"},
	{"$pbkdf2-hmac-md4$1000$3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031$b068b5e87fb2b546964e8fa7cb1e8a22", "magnum"},
	{"$pbkdf2-hmac-md4$1000$30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334$66b310420623a2c1ebc43b22ac3e9226", "magnum"},
	{NULL}
};

int pbkdf2_hmac_md4_valid(char *ciphertext, struct fmt_main *self)
{
	char *ptr, *ctcopy, *keeptr;
	size_t len;
	char *delim;

	if (strncmp(ciphertext, PBKDF2_MD4_FORMAT_TAG, PBKDF2_MD4_TAG_LEN))
		return 0;
	if (strlen(ciphertext) > PBKDF2_MD4_MAX_CIPHERTEXT_LENGTH)
		return 0;
	ciphertext += PBKDF2_MD4_TAG_LEN;
	delim = strchr(ciphertext, '.') ? "." : "$";
	if (!(ctcopy = strdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	if (!(ptr = strtokm(ctcopy, delim)))
		goto error;
	if (!atoi(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, delim)))
		goto error;
	len = strlen(ptr); // salt hex length
	if (len > 2 * PBKDF2_MDx_MAX_SALT_SIZE || len & 1)
		goto error;
	if (!ishexlc(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, delim)))
		goto error;
	len = strlen(ptr); // binary hex length
	if (len < PBKDF2_MDx_BINARY_SIZE || len > PBKDF2_MDx_MAX_BINARY_SIZE || len & 1)
		goto error;
	if (!ishexlc(ptr))
		goto error;
	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

char *pbkdf2_hmac_md4_split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[PBKDF2_MD4_MAX_CIPHERTEXT_LENGTH + 1];
	char *cp;
	strnzcpy(out, ciphertext, sizeof(out));
	strlwr(out);
	cp = strchr(out, '.');
	while (cp) {
		*cp = '$';
		cp = strchr(cp, '.');
	}
	return out;
}

void *pbkdf2_hmac_md4_binary(char *ciphertext)
{
	static union {
		unsigned char c[PBKDF2_MDx_BINARY_SIZE];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	int i;
	char *p;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < PBKDF2_MDx_BINARY_SIZE && *p; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
#if 0
	dump_stuff_msg(__FUNCTION__, out, PBKDF2_MDx_BINARY_SIZE);
#endif
	return out;
}

/* Check the FULL binary, just for good measure. There is not a chance we'll
   have a false positive here but this function is not performance critical. */
int pbkdf2_hmac_md4_cmp_exact(char *key, char *source, unsigned char *salt, int salt_len, int iterations)
{
	int i = 0, len, result;
	char *p;
	unsigned char *binary, *crypt;

	p = strrchr(source, '$') + 1;
	len = strlen(p) / 2;

	if (len == PBKDF2_MDx_BINARY_SIZE) return 1;

	binary = mem_alloc(len);
	crypt = mem_alloc(len);

	while (*p) {
		binary[i++] = (atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	pbkdf2_md4((const unsigned char*)key,
	            strlen(key),
	            salt, salt_len,
	            iterations, crypt, len, 0);
	result = !memcmp(binary, crypt, len);
#if 0
	dump_stuff_msg("hash binary", binary, len);
	dump_stuff_msg("calc binary", crypt, len);
#endif
	MEM_FREE(binary);
	MEM_FREE(crypt);
	if (!result)
		fprintf(stderr, "\npbkdf2-hmac-md4: Warning: Partial match for '%s'.\n"
		        "This is a bug or a malformed input line of:\n%s\n",
		        key, source);
	return result;
}


/*
 * Common stuff for pbkdf2-md5 hashes
 */

struct fmt_tests pbkdf2_hmac_md5_common_tests[] = {
	{"$pbkdf2-hmac-md5$1$73616c74$f31afb6d931392daa5e3130f47f9a9b6", "password"},
	{"$pbkdf2-hmac-md5$1000$38333335343433323338$f445d6d0ed5cbe9fc12c03ea9530c1c6", "hashcat"},
	{"$pbkdf2-hmac-md5$1000$38333335343433323338$f445d6d0ed5cbe9fc12c03ea9530c1c6f79e7886a6af1552b40f3704a8b87847", "hashcat"},
	{"$pbkdf2-hmac-md5$10000$6d61676e756d$8802b8d3bc1ba8fe973313a3606d0db3", "Borkum"},
	{"$pbkdf2-hmac-md5$10000$6d61676e756d$0d21b39b60a304aa649b5da493c8e202", "Riff"},
	{"$pbkdf2-hmac-md5$1000$303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930$372795e78c4f0e4a12eb71b2dc9642a0", "password"},
	{"$pbkdf2-hmac-md5$1000$30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031$4c2daa842d2e43cb32ddf0451919efd9", "password"},
	{"$pbkdf2-hmac-md5$1000$3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132$e9eb42dd6714d462507ba1b7b947c858", "password"},
	{"$pbkdf2-hmac-md5$1000$303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839$630ddb7d05c2d0ca574016ace337a7dc", "password"},
	{"$pbkdf2-hmac-md5$1000$30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930$73d33406e3ddeb4ba70a3589f17d0107", "password"},
	{"$pbkdf2-hmac-md5$1000$3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031$62c145b5e81587f4f1f4b8fcf9e87a88", "password"},
	{"$pbkdf2-hmac-md5$1000$30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334$f5fd04950d28c8f76cd10d455d4ad80c", "password"},
	{NULL}
};

int pbkdf2_hmac_md5_valid(char *ciphertext, struct fmt_main *self)
{
	char *ptr, *ctcopy, *keeptr;
	size_t len;
	char *delim;

	if (strncmp(ciphertext, PBKDF2_MD5_FORMAT_TAG, PBKDF2_MD5_TAG_LEN))
		return 0;
	if (strlen(ciphertext) > PBKDF2_MD5_MAX_CIPHERTEXT_LENGTH)
		return 0;
	ciphertext += PBKDF2_MD5_TAG_LEN;
	delim = strchr(ciphertext, '.') ? "." : "$";
	if (!(ctcopy = strdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	if (!(ptr = strtokm(ctcopy, delim)))
		goto error;
	if (!atoi(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, delim)))
		goto error;
	len = strlen(ptr); // salt hex length
	if (len > 2 * PBKDF2_MDx_MAX_SALT_SIZE || len & 1)
		goto error;
	if (!ishexlc(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, delim)))
		goto error;
	len = strlen(ptr); // binary hex length
	if (len < PBKDF2_MDx_BINARY_SIZE || len > PBKDF2_MDx_MAX_BINARY_SIZE || len & 1)
		goto error;
	if (!ishexlc(ptr))
		goto error;
	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

char *pbkdf2_hmac_md5_split(char *ciphertext, int index, struct fmt_main *self) {
	static char out[PBKDF2_MD5_MAX_CIPHERTEXT_LENGTH + 1];
	char *cp;
	strnzcpy(out, ciphertext, sizeof(out));
	strlwr(out);
	cp = strchr(out, '.');
	while (cp) {
		*cp = '$';
		cp = strchr(cp, '.');
	}
	return out;
}

void *pbkdf2_hmac_md5_binary(char *ciphertext)
{
	static union {
		unsigned char c[PBKDF2_MDx_BINARY_SIZE];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i, len;

	p = strrchr(ciphertext, '$') + 1;
	len = strlen(p) / 2;
	for (i = 0; i < len && *p; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
#if 0
	dump_stuff_msg(__FUNCTION__, out, PBKDF2_MDx_BINARY_SIZE);
#endif
	return out;
}


int pbkdf2_hmac_md5_cmp_exact(char *key, char *source, unsigned char *salt, int salt_len, int iterations)
{
	int i = 0, len, result;
	char *p;
	unsigned char *binary, *crypt;

	p = strrchr(source, '$') + 1;
	len = strlen(p) / 2;

	if (len == PBKDF2_MDx_BINARY_SIZE) return 1;

	binary = mem_alloc(len);
	crypt = mem_alloc(len);

	while (*p) {
		binary[i++] = (atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	pbkdf2_md5((const unsigned char*)key,
	            strlen(key),
	            salt, salt_len,
	            iterations, crypt, len, 0);
	result = !memcmp(binary, crypt, len);
#if 0
	dump_stuff_msg("hash binary", binary, len);
	dump_stuff_msg("calc binary", crypt, len);
#endif
	MEM_FREE(binary);
	MEM_FREE(crypt);
	if (!result)
		fprintf(stderr, "\npbkdf2-hmac-md5: Warning: Partial match for '%s'.\n"
		        "This is a bug or a malformed input line of:\n%s\n",
		        key, source);
	return result;
}

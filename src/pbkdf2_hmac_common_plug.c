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
#include "common.h"
#include "base64_convert.h"
#include "pbkdf2_hmac_common.h"
#define OPENCL_FORMAT
#define PBKDF2_HMAC_MD4_ALSO_INCLUDE_CTX 1
#include "pbkdf2_hmac_md4.h"
#define PBKDF2_HMAC_MD5_ALSO_INCLUDE_CTX 1
#include "pbkdf2_hmac_md5.h"
#define PBKDF2_HMAC_SHA1_ALSO_INCLUDE_CTX 1
#include "pbkdf2_hmac_sha1.h"
#define PBKDF2_HMAC_SHA512_ALSO_INCLUDE_CTX 1
#include "pbkdf2_hmac_sha512.h"


static void dump_hex(const void *msg, void *x, unsigned int size)
{
	unsigned int i;

	printf("%s : ", (char *)msg);
	for (i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)x)[i]);
		if ( (i%4)==3 )
		printf(" ");
	}
	printf("\n");
}

/**************************************
 * Common stuff for pbkdf2-md4 hashes
 **************************************/

struct fmt_tests pbkdf2_hmac_md4_common_tests[] = {
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
	{"$pbkdf2-hmac-md4$1000$3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435$111ea1eb1df55fb67ac2c9bbd6ee70dd", "password"},
	{"$pbkdf2-hmac-md4$1000$303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536$6f85c1be05f0ee93b197a49201140116", "password"},
	{"$pbkdf2-hmac-md4$1000$3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738$4440cfa64758fff2475944eb547e0d44", "password"},
	{"$pbkdf2-hmac-md4$1000$30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233$555cbe65cad0ce46d1076859cdf1ef03", "password"},
	{"$pbkdf2-hmac-md4$1000$303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435$258e2650160674b004d23ccec71033ea", "password"},
	{"$pbkdf2-hmac-md4$1000$30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536$69609747c1240b892e0b88d43aef2608", "password"},
	{"$pbkdf2-hmac-md4$1000$3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637$e3fbaec1582c2f5207d95c52ead51643", "password"},
	{"$pbkdf2-hmac-md4$1000$303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738$0a5d2fd1a21d39de308d94aaa96acba5", "password"},
	{"$pbkdf2-hmac-md4$1000$3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738$56f59d132dcc56a4bebf44d265f1b43f", "password"},
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
	if (!(ctcopy = xstrdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	if (!(ptr = strtokm(ctcopy, delim)))
		goto error;
	if (!atoi(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, delim)))
		goto error;
	len = strlen(ptr); // salt hex length
	if (len > 2 * PBKDF2_32_MAX_SALT_SIZE || len & 1)
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
	strnzcpylwr(out, ciphertext, sizeof(out));
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
	dump_hex(__FUNCTION__, out, PBKDF2_MDx_BINARY_SIZE);
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
	dump_hex("hash binary", binary, len);
	dump_hex("calc binary", crypt, len);
#endif
	MEM_FREE(binary);
	MEM_FREE(crypt);
	if (!result)
		fprintf(stderr, "\npbkdf2-hmac-md4: Warning: Partial match for '%s'.\n"
		        "This is a bug or a malformed input line of:\n%s\n",
		        key, source);
	return result;
}


/**************************************
 * Common stuff for pbkdf2-md5 hashes
 **************************************/

struct fmt_tests pbkdf2_hmac_md5_common_tests[] = {
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
	{"$pbkdf2-hmac-md5$1000$303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536$012c74ecdd2c009dfa9d6d176a299551", "password"},
	{"$pbkdf2-hmac-md5$1000$30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637$d45fa78d145cb6e86ed7ffc67cf25b8a", "password"},
	{"$pbkdf2-hmac-md5$1000$3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738$b2c0fac55ca6068880d221e96137628d", "password"},
	{"$pbkdf2-hmac-md5$1000$30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233$5607f777ed33ece96442f51bbb41bf78", "password"},
	{"$pbkdf2-hmac-md5$1000$303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435$def76b9cb3c2773baf26b91bb5a48da1", "password"},
	{"$pbkdf2-hmac-md5$1000$30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536$2e3a60bb1cd56831cb2ecf52529375f2", "password"},
	{"$pbkdf2-hmac-md5$1000$3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637$ec41f832048f530d23ccd7e0becfb755", "password"},
	{"$pbkdf2-hmac-md5$1000$303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738$cfe5e9745081b369afc5f3a0f952ca8a", "password"},
	{"$pbkdf2-hmac-md5$1000$3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738$d79edf4f6fca3411b2f635048b02751e", "password"},
	{"$pbkdf2-hmac-md5$1$73616c74$f31afb6d931392daa5e3130f47f9a9b6", "password"},
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
	if (!(ctcopy = xstrdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	if (!(ptr = strtokm(ctcopy, delim)))
		goto error;
	if (!atoi(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, delim)))
		goto error;
	len = strlen(ptr); // salt hex length
	if (len > 2 * PBKDF2_32_MAX_SALT_SIZE || len & 1)
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
	strnzcpylwr(out, ciphertext, sizeof(out));
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
	int i;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < PBKDF2_MDx_BINARY_SIZE; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
#if 0
	dump_hex(__FUNCTION__, out, PBKDF2_MDx_BINARY_SIZE);
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
	dump_hex("hash binary", binary, len);
	dump_hex("calc binary", crypt, len);
#endif
	MEM_FREE(binary);
	MEM_FREE(crypt);
	if (!result)
		fprintf(stderr, "\npbkdf2-hmac-md5: Warning: Partial match for '%s'.\n"
		        "This is a bug or a malformed input line of:\n%s\n",
		        key, source);
	return result;
}


/**************************************
 * Common stuff for pbkdf2-sha1 hashes
 **************************************/

struct fmt_tests pbkdf2_hmac_sha1_common_tests[] = {
	{"$pbkdf2-hmac-sha1$1000.fd11cde0.27de197171e6d49fc5f55c9ef06c0d8751cd7250", "3956"},
	{"$pbkdf2-hmac-sha1$1000$6926d45e$231c561018a4cee662df7cd4a8206701c5806af9", "1234"},
	{"$pbkdf2-hmac-sha1$1000.98fcb0db.37082711ff503c2d2dea9a5cf7853437c274d32e", "5490"},
	// Long password
	{"$pbkdf2-hmac-sha1$1000.6834476f733353333654315a5a31494f.1932a843a69dc1e38a29d2691a7abf27ecaa6d55", "Very long string to test larger than sixty-four characters candidate"},
	// WPA-PSK DK (raw key as stored by some routers):
	// iterations is always 4096.
	// ESSID was "Harkonen" - converted to hex 4861726b6f6e656e.
	// Only first 20 bytes (40 hex chars) of key is required but if
	// you supply all 32 (64) of them, they will be double checked
	// without sacrificing speed.
	// Please also note that you should run such hashes with --min-len=8,
	// because WPAPSK passwords can't be shorter than that.
	{"$pbkdf2-hmac-sha1$4096$4861726b6f6e656e$ee51883793a6f68e9615fe73c80a3aa6f2dd0ea537bce627b929183cc6e57925", "12345678"},
	// these get converted in prepare()
	// http://pythonhosted.org/passlib/lib/passlib.hash.atlassian_pbkdf2_sha1.html
	{"{PKCS5S2}DQIXJU038u4P7FdsuFTY/+35bm41kfjZa57UrdxHp2Mu3qF2uy+ooD+jF5t1tb8J", "password"},
	// http://pythonhosted.org/passlib/lib/passlib.hash.cta_pbkdf2_sha1.html
	{"$p5k2$2710$oX9ZZOcNgYoAsYL-8bqxKg==$AU2JLf2rNxWoZxWxRCluY0u6h6c=", "password" },
	// tests of long salts at areas where bugs could be found in the openCL code.
	{"$pbkdf2-hmac-sha1$1000.3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738.8f7c89f74233f78f6c8ace00696cf6ed09ae43f4", "password"}, // 179
	{"$pbkdf2-hmac-sha1$1000.303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536.ce3c993d95655e452c43e44889091c1b432dc1ed", "password"},  // 117
	{"$pbkdf2-hmac-sha1$1000.3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435.bd2aa5c1022735c2813920f26d5349aefc6317cf", "password"},  // 116
	{"$pbkdf2-hmac-sha1$1000.30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334.be2cfcaf566d4fcd45670b52fb0bd0372a0b9b2f", "password"},  // 115
	{"$pbkdf2-hmac-sha1$1000.303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435.0d9362a8ff1f7fa273e43bcd89bf5c4d843f4e79", "password"},  // 66
	{"$pbkdf2-hmac-sha1$1000.3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334.c5d191d8cabe46950e148bcf4b9043b7c4de1157", "password"},  // 65
	{"$pbkdf2-hmac-sha1$1000.30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233.08f0596a8cef6e905e882b0ecea58dcbf3989a8f", "password"},  // 64
	{"$pbkdf2-hmac-sha1$1000.303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132.6bb2cf259db7971a304746ce590ba68d908eea64", "password"},  // 63
	{"$pbkdf2-hmac-sha1$1000.3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031.c2dd966f13812d4c6012bfa9c0326b308e7a3dd5", "password"},    // 62
	{"$pbkdf2-hmac-sha1$1000.30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930.0743822bd75e509ce5ee4028d59fb0eaa00404a0", "password"},      // 61
	{"$pbkdf2-hmac-sha1$1000.303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839.48aac2e43431406af6fa08cb4ad23d98101bff04", "password"},        // 60
	{"$pbkdf2-hmac-sha1$1000.303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233.3a025719f3f4120d0172e56d504790916e0be397", "password"},    // 54
	{"$pbkdf2-hmac-sha1$1000.3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132.fae2eacc292606642bbf4eb74c35e18bc5f6297b", "password"},      // 53
	{"$pbkdf2-hmac-sha1$1000.30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031.c13037123928b5c895df01e2e371752d447495ca", "password"},        // 52
	{"$pbkdf2-hmac-sha1$1000.303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930.a145d99036ea8d7ec08b5b10b3fa2b5227482d16", "password"},          // 51
	{NULL}
};

int pbkdf2_hmac_sha1_valid(char *ciphertext, struct fmt_main *self) {
	char *ptr, *ctcopy, *keeptr;
	size_t len;
	char *delim;

	if (strncasecmp(ciphertext, PBKDF2_SHA1_FORMAT_TAG, PBKDF2_SHA1_TAG_LEN))
		return 0;
	if (strlen(ciphertext) > PBKDF2_SHA1_MAX_CIPHERTEXT_LENGTH)
		return 0;
	ciphertext += PBKDF2_SHA1_TAG_LEN;
	delim = strchr(ciphertext, '.') ? "." : "$";
	if (!(ctcopy = xstrdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	if (!(ptr = strtokm(ctcopy, delim)))
		goto error;
	if (!atou(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, delim)))
		goto error;
	len = strlen(ptr); // salt hex length
	if (len > 2 * PBKDF2_32_MAX_SALT_SIZE || len & 1)
		goto error;
	if (!ishex(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, delim)))
		goto error;
	len = strlen(ptr); // binary hex length
	if (len < PBKDF2_SHA1_BINARY_SIZE || len > PBKDF2_SHA1_MAX_BINARY_SIZE || len & 1)
		goto error;
	if (!ishex(ptr))
		goto error;
	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

char *pbkdf2_hmac_sha1_split(char *ciphertext, int index, struct fmt_main *self) {
	static char out[PBKDF2_SHA1_MAX_CIPHERTEXT_LENGTH + 1];
	char *cp;

	strnzcpylwr(out, ciphertext, sizeof(out));
	cp = strchr(out, '.');
	while (cp) {
		*cp = '$';
		cp = strchr(cp, '.');
	}
	return out;
}

char *pbkdf2_hmac_sha1_prepare(char *fields[10], struct fmt_main *self)
{
	static char Buf[PBKDF2_SHA1_MAX_CIPHERTEXT_LENGTH + 1];

	if (strncmp(fields[1], PKCS5S2_TAG, PKCS5S2_TAG_LEN) &&
	    strncmp(fields[1], PK5K2_TAG, PK5K2_TAG_LEN))
		return fields[1];

	if (!strncmp(fields[1], PKCS5S2_TAG, PKCS5S2_TAG_LEN)) {
		char tmp[120+1];
		if (strlen(fields[1]) > 75) return fields[1];
		//{"{PKCS5S2}DQIXJU038u4P7FdsuFTY/+35bm41kfjZa57UrdxHp2Mu3qF2uy+ooD+jF5t1tb8J", "password"},
		//{"$pbkdf2-hmac-sha1$10000$0d0217254d37f2ee0fec576cb854d8ff$edf96e6e3591f8d96b9ed4addc47a7632edea176bb2fa8a03fa3179b75b5bf09", "password"},
		base64_convert(&(fields[1][PKCS5S2_TAG_LEN]), e_b64_mime, strlen(&(fields[1][PKCS5S2_TAG_LEN])), tmp, e_b64_hex, sizeof(tmp), 0, 0);
		sprintf(Buf, "%s10000$%32.32s$%s", PBKDF2_SHA1_FORMAT_TAG, tmp, &tmp[32]);
		return Buf;
	}

	if (!strncmp(fields[1], PK5K2_TAG, PK5K2_TAG_LEN)) {
		char tmps[240+1], tmph[60+1], *cp, *cp2;
		unsigned iter=0;
		// salt was listed as 1024 bytes max. But our max salt size is 115 bytes (~150 base64 bytes).
		if (strlen(fields[1]) > 186) return fields[1];
		//{"$p5k2$2710$oX9ZZOcNgYoAsYL-8bqxKg==$AU2JLf2rNxWoZxWxRCluY0u6h6c=", "password" },
		//{"$pbkdf2-hmac-sha1$10000$a17f5964e70d818a00b182fef1bab12a$014d892dfdab3715a86715b144296e634bba87a7", "password"},
		cp = fields[1];
		cp += PK5K2_TAG_LEN;
		while (*cp && *cp != '$') {
			iter *= 0x10;
			if (atoi16[ARCH_INDEX(*cp)] == 0x7f) return fields[1];
			iter += atoi16[ARCH_INDEX(*cp)];
			++cp;
		}
		if (*cp != '$') return fields[1];
		++cp;
		cp2 = strchr(cp, '$');
		if (!cp2) return fields[1];
		base64_convert(cp, e_b64_mime, cp2-cp, tmps, e_b64_hex, sizeof(tmps), flg_Base64_MIME_DASH_UNDER, 0);
		if (strlen(tmps) > 115) return fields[1];
		++cp2;
		base64_convert(cp2, e_b64_mime, strlen(cp2), tmph, e_b64_hex, sizeof(tmph), flg_Base64_MIME_DASH_UNDER, 0);
		if (strlen(tmph) != 40) return fields[1];
		sprintf(Buf, "%s%d$%s$%s", PBKDF2_SHA1_FORMAT_TAG, iter, tmps, tmph);
		return Buf;
	}
	return fields[1];
}

void *pbkdf2_hmac_sha1_binary(char *ciphertext) {
	static union {
		unsigned char c[PBKDF2_SHA1_MAX_BINARY_SIZE];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i, len;

	p = strrchr(ciphertext, '$') + 1;
	len = strlen(p) >> 1;
	if (len > PBKDF2_SHA1_MAX_BINARY_SIZE)
		len = PBKDF2_SHA1_MAX_BINARY_SIZE;
	memset(buf.c, 0, sizeof(buf.c));
	for (i = 0; i < len; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return out;
}

int pbkdf2_hmac_sha1_cmp_exact(char *key, char *source, unsigned char *salt, int salt_len, int iterations) {
	int i = 0, len, result;
	char *p;
	char delim;
	unsigned char *binary, *crypt;

	delim = strchr(source, '.') ? '.' : '$';
	p = strrchr(source, delim) + 1;
	len = strlen(p) / 2;

	if (len == PBKDF2_SHA1_BINARY_SIZE) return 1;

	binary = mem_alloc(len);
	crypt = mem_alloc(len);

	while (*p) {
		binary[i++] = (atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	pbkdf2_sha1((const unsigned char*)key,
	            strlen(key),
	            salt, salt_len,
	            iterations, crypt, len, 0);
	result = !memcmp(binary, crypt, len);
#if 0
	dump_hex("hash binary", binary, len);
	dump_hex("calc binary", crypt, len);
#endif
	MEM_FREE(binary);
	MEM_FREE(crypt);
	if (!result)
		fprintf(stderr, "\npbkdf2-hmac-sha1: Warning: Partial match for '%s'.\n"
		        "This is a bug or a malformed input line of:\n%s\n",
		        key, source);
	return result;
}

/**************************************
 * Common stuff for pbkdf2-sha256 hashes
 **************************************/
/*
	Testcases generated by passlib, format: $pbkdf2-256$rounds$salt$checksum
	salt and checksum are encoded in "adapted base64"
*/
struct fmt_tests pbkdf2_hmac_sha256_common_tests[] = {
	/* Low iteration test vectors for comparison */
	{"$pbkdf2-sha256$1000$b1dWS2dab3dKQWhPSUg3cg$UY9j5wlyxtsJqhDKTqua8Q3fMp0ojc2pOnErzr8ntLE", "magnum"},
	{"$pbkdf2-sha256$1000$amkzNk9tOXJVZ043QTZ1dA$YIpbl0hjiV9UFMszHNDlJIa0bcObTIkPzT6XvhJPcMM", "bonum"},
	{"$pbkdf2-sha256$1000$WEI2ZTVJcWdTZ3JQQjVnMA$6n1V7Ffm1tsB4q7uk4mi8z5Sco.fL28pScSSc5Qr27Y", "Ripper"},
	{"$pbkdf2-sha256$10000$UWthWUhuRXdPZkZPMnF0Ug$l/T9Bmy7qtaPEvbPC2qAfYuj5RAxTbv8I.hSTfyIwYg", "10K worth of looping"},
	{"$pbkdf2-sha256$10000$Sm1hNlBZWDVYd1FWT3FUUQ$foweCatpTeXpaba1tS7fJTPUquByBb5oI8vilOSspaI", "moebusring"},
	{"$pbkdf2-sha256$12000$2NtbSwkhRChF6D3nvJfSGg$OEWLc4keep8Vx3S/WnXgsfalb9q0RQdS1s05LfalSG4", ""},
	{"$pbkdf2-sha256$12000$fK8VAoDQuvees5ayVkpp7Q$xfzKAoBR/Iaa68tjn.O8KfGxV.zdidcqEeDoTFvDz2A", "1"},
	{"$pbkdf2-sha256$12000$GoMQYsxZ6/0fo5QyhtAaAw$xQ9L6toKn0q245SIZKoYjCu/Fy15hwGme9.08hBde1w", "12"},
	{"$pbkdf2-sha256$12000$6r3XWgvh/D/HeA/hXAshJA$11YY39OaSkJuwb.ONKVy5ebCZ00i5f8Qpcgwfe3d5kY", "123"},
	{"$pbkdf2-sha256$12000$09q711rLmbMWYgwBIGRMqQ$kHdAHlnQ1i1FHKBCPLV0sA20ai2xtYA1Ev8ODfIkiQg", "1234"},
	{"$pbkdf2-sha256$12000$Nebce08pJcT43zuHUMo5Rw$bMW/EsVqy8tMaDecFwuZNEPVfQbXBclwN78okLrxJoA", "openwall"},
	{"$pbkdf2-sha256$12000$mtP6/39PSQlhzBmDsJZS6g$zUXxf/9XBGrkedXVwhpC9wLLwwKSvHX39QRz7MeojYE", "password"},
	{"$pbkdf2-sha256$12000$35tzjhGi9J5TSilF6L0XAg$MiJA1gPN1nkuaKPVzSJMUL7ucH4bWIQetzX/JrXRYpw", "pbkdf2-sha256"},
	{"$pbkdf2-sha256$12000$sxbCeE8pxVjL2ds7hxBizA$uIiwKdo9DbPiiaLi1y3Ljv.r9G1tzxLRdlkD1uIOwKM", " 15 characters "},
	{"$pbkdf2-sha256$12000$CUGI8V7rHeP8nzMmhJDyXg$qjq3rBcsUgahqSO/W4B1bvsuWnrmmC4IW8WKMc5bKYE", " 16 characters__"},
	{"$pbkdf2-sha256$12000$FmIM4VxLaY1xLuWc8z6n1A$OVe6U1d5dJzYFKlJsZrW1NzUrfgiTpb9R5cAfn96WCk", " 20 characters______"},
	{"$pbkdf2-sha256$12000$fA8BAMAY41wrRQihdO4dow$I9BSCuV6UjG55LktTKbV.bIXtyqKKNvT3uL7JQwMLp8", " 24 characters______1234"},
	{"$pbkdf2-sha256$12000$/j8npJTSOmdMKcWYszYGgA$PbhiSNRzrELfAavXEsLI1FfitlVjv9NIB.jU1HHRdC8", " 28 characters______12345678"},
	{"$pbkdf2-sha256$12000$xfj/f6/1PkcIoXROCeE8Bw$ci.FEcPOKKKhX5b3JwzSDo6TGuYjgj1jKfCTZ9UpDM0", " 32 characters______123456789012"},
	{"$pbkdf2-sha256$12000$6f3fW8tZq7WWUmptzfmfEw$GDm/yhq1TnNR1MVGy73UngeOg9QJ7DtW4BnmV2F065s", " 40 characters______12345678901234567890"},
	{"$pbkdf2-sha256$12000$dU5p7T2ndM7535tzjpGyVg$ILbppLkipmonlfH1I2W3/vFMyr2xvCI8QhksH8DWn/M", " 55 characters______________________________________end"},
	{"$pbkdf2-sha256$12000$iDFmDCHE2FtrDaGUEmKMEaL0Xqv1/t/b.x.DcC6lFEI$tUdEcw3csCnsfiYbFdXH6nvbftH8rzvBDl1nABeN0nE", "salt length = 32"},
	{"$pbkdf2-sha256$12000$0zoHwNgbIwSAkDImZGwNQUjpHcNYa43xPqd0DuH8H0OIUWqttfY.h5DynvPeG.O8N.Y$.XK4LNIeewI7w9QF5g9p5/NOYMYrApW03bcv/MaD6YQ", "salt length = 50"},
	{"$pbkdf2-sha256$12000$HGPMeS9lTAkhROhd653Tuvc.ZyxFSOk9x5gTYgyBEAIAgND6PwfAmA$WdCipc7O/9tTgbpZvcz.mAkIDkdrebVKBUgGbncvoNw", "salt length = 40"},
	{"$pbkdf2-sha256$12001$ay2F0No7p1QKgVAqpbQ2hg$UbKdswiLpjc5wT8Zl2M6VlE2cNiKuhAUntGciP8JjPw", "test"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkw$RvyFSU8DM6qYW79urz7KPz/zzyUlHl5NlHULlsW1WKA", "51 byte salt"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMQ$kQe4YOwY0LY5zCNNyr5UvnpeBrx/qxuIwntFnzW2zb8", "52 byte salt"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5$QoIK6793HiOBzPq34H89QvcQDB5bksb/.7.TCLQFOeg", "60 byte salt"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MA$jDBOWzng7Tyk9jS0T3F/9JWhTptuRh9y./FMpIkqf3I", "61 byte salt"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE$8xnT1aRPA7r8aTZgoJqzCJxxzOZ/hn41jGAFC9nJpuU", "62 byte salt"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA$HZ5Vlvz/6CptMcpvAC04lRYplo8C.Roq0gi8P7Dvj8g", "115 byte salt"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg$94Z71JhWYUP2E0IrQrexc8AMhHzVB4bwkxh7n0FCnns", "password"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMg$9XOhVIMUQ8.jq9ElZ/PoXwgQhCsRzNPTDJLnaQ.Whwo", "password"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx$ddDC10btHUZElFF.J8KP6YAbGah9QYXK0vlZZTHEFJ0", "password"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA$o76M3BIhjfSOxNHQ1RSsCBVuWEjalMTK1zs/MAIhqWI", "password"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OQ$k8MzH7InlAVl0knFdU2pHc2vf3jKHX2o9lrXr9xInBE", "password"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4$HtPT2SqQ6207CtggpYf/t3WqVNykNsDdiiDlxC1w6jQ", "password"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc$5XvUDwN4ZcEW2F8ECv6P.bjdms632tUADE4dtjV3HMI", "password"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Ng$M7/bhOd8vjr9u5gpaEu/YjYEURVjREGQjF.o2m.m/tI", "password"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1$pvuL6YjonZ/UN8BGHCi9FAtPqhqvoWLsU8q4paqkqsw", "password"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE$Tgd/agvDayut4M8YboPLLVm8CSfSVrY3ABUc09y86LY", "password"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2$CPXOC5elMM/3yjyAR4jzWM5lHeip2iMkIuRhWBJueeM", "password"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU$jYf7bCEBByYmvYB/RzJIe2xTQCf8dpTFtLc1pqgMry8", "password"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA$UoukLbWU8MwwFaW/nj5x09IfukfIbdjC3IQiz7LiogI", "password"},
	{"$pbkdf2-sha256$12000$MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz$iII/U6157WHgHfIatBb/o1rXQithKBN6ykgJU/I0Wpc", "password"},
	// cisco type 8 hashes.  20k iterations, different base-64 (same as WPA).  Also salt is used RAW, it is not base64 decoded prior to usage
	{"$8$dsYGNam3K1SIJO$7nv/35M/qr6t.dVc7UY9zrJDWRVqncHub1PE9UlMQFs", "cisco"},
	{"$8$6NHinlEjiwvb5J$RjC.H.ydVb34wDLqJvfjyG1ubxYKpfXqv.Ry9mtrNBY", "password"},
	{"$8$lGO8juTOQLPCHw$cBv2WEaFCLUA24Z48CKUGixIywyGFP78r/slQcMXr3M", "JtR"},
	{NULL}
};

int pbkdf2_hmac_sha256_valid(char *ciphertext, struct fmt_main *self) {
	int saltlen = 0;
	char *p, *c = ciphertext;

	if (strncmp(ciphertext, FORMAT_TAG_CISCO8, FORMAT_TAG_CISCO8_LEN) == 0) {
		char *f[10];
		f[1] = ciphertext;
		ciphertext = pbkdf2_hmac_sha256_prepare(f, self);
	}
	if (strncmp(ciphertext, PBKDF2_SHA256_FORMAT_TAG, PBKDF2_SHA256_TAG_LEN) != 0)
		return 0;
	if (strlen(ciphertext) < 44 + PBKDF2_SHA256_TAG_LEN)
		return 0;
	if (strlen(ciphertext) > PBKDF2_SHA256_MAX_CIPHERTEXT_LENGTH)
		return 0;
	c += PBKDF2_SHA256_TAG_LEN;
	if (strtol(c, NULL, 10) == 0)
		return 0;
	c = strchr(c, '$');
	if (c == NULL)
		return 0;
	c++;
	p = strchr(c, '$');
	if (p == NULL)
		return 0;
	saltlen = base64_valid_length(c, e_b64_mime, flg_Base64_MIME_PLUS_TO_DOT, 0);
	c += saltlen;
	saltlen = B64_TO_RAW_LEN(saltlen);
	if (saltlen > PBKDF2_32_MAX_SALT_SIZE)
		return 0;
	if (*c != '$') return 0;
	c++;
	if (base64_valid_length(c, e_b64_mime, flg_Base64_MIME_PLUS_TO_DOT, 0) != 43)
		return 0;
	return 1;
}

char *pbkdf2_hmac_sha256_prepare(char *fields[10], struct fmt_main *self) {
	static char Buf[PBKDF2_SHA256_MAX_CIPHERTEXT_LENGTH + 1];
	char tmp[43+1], *cp;

	if (strncmp(fields[1], FORMAT_TAG_CISCO8, FORMAT_TAG_CISCO8_LEN) != 0)
		return fields[1];
	if (strlen(fields[1]) != 4+14+43)
		return fields[1];
	sprintf(Buf, "%s20000$%14.14s$%s", PBKDF2_SHA256_FORMAT_TAG, &(fields[1][FORMAT_TAG_CISCO8_LEN]),
		base64_convert_cp(&(fields[1][FORMAT_TAG_CISCO8_LEN+14+1]), e_b64_crypt, 43, tmp, e_b64_mime, sizeof(tmp), flg_Base64_NO_FLAGS, 0));
	cp = strchr(Buf, '+');
	while (cp) {
		*cp = '.';
		cp = strchr(cp, '+');
	}
	return Buf;
}

void *pbkdf2_hmac_sha256_binary(char *ciphertext) {
	static union {
		char c[PBKDF2_SHA256_BINARY_SIZE];
		uint32_t dummy;
	} buf;
	char *ret = buf.c;
	char *c = ciphertext;
	c += PBKDF2_SHA256_TAG_LEN;
	c = strchr(c, '$') + 1;
	c = strchr(c, '$') + 1;
#ifdef DEBUG
	assert(strlen(c) == 43);
#endif
	base64_convert(c, e_b64_mime, 43, buf.c, e_b64_raw, sizeof(buf.c), flg_Base64_MIME_PLUS_TO_DOT|flg_Base64_DONOT_NULL_TERMINATE, 0);
	return ret;
}

/**************************************
 * Common stuff for pbkdf2-sha512 hashes
 **************************************/

struct fmt_tests pbkdf2_hmac_sha512_common_tests[] = {
	{"$pbkdf2-hmac-sha512$1000.6b635263736c70346869307a304b5276.80cf814855f2299103a6084366e41d7e14f9894b05ed77fa19881d28f06cde18da9ab44972cd00496843371ce922c70e64f3862b036b59b581fe32fc4408fe49", "magnum"},
	{"$pbkdf2-hmac-sha512$1000.55636d4344326e537236437677674a46.e7a60f0cf216c40b31cc6fc34d6a0093c978bbb49d6934dbca286b63fe28473bd3683917807173aef122e5a6bc5c7b4178ed6225f414c994df46013754a52177", "Ripper"},
	/* GRUB hash, GRUB format */
	{"grub.pbkdf2.sha512.10000.4483972AD2C52E1F590B3E2260795FDA9CA0B07B96FF492814CA9775F08C4B59CD1707F10B269E09B61B1E2D11729BCA8D62B7827B25B093EC58C4C1EAC23137.DF4FCB5DD91340D6D31E33423E4210AD47C7A4DF9FA16F401663BF288C20BF973530866178FE6D134256E4DBEFBD984B652332EED3ACAED834FEA7B73CAE851D", "password"},
	/* Canonical format */
	{"$pbkdf2-hmac-sha512$10000.82dbab96e072834d1f725db9aded51e703f1d449e77d01f6be65147a765c997d8865a1f1ab50856aa3b08d25a5602fe538ad0757b8ca2933fe8ca9e7601b3fbf.859d65960e6d05c6858f3d63fa35c6adfc456637b4a0a90f6afa7d8e217ce2d3dfdc56c8deaca217f0864ae1efb4a09b00eb84cf9e4a2723534f34e26a279193", "openwall"},
//  {"$pbkdf2-hmac-sha512$10000.2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e.cd9f205b20c3cc9699b1304d02cfa4dd2f69adda583402e99d1102911b14519653f4d2d09d0c8576d745ec9fa14888e0b3f32b254bb4d80aad2bd8b0c433e56d", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345"},
	/* max length password (and longer salt) made by pass_gen.pl */
	/*110*/
	{"$pbkdf2-hmac-sha512$10000.78783334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334.33cfd654a173d39fcae804ba07744d276d184ca85f1e422a623aa7eec66b6bc372074551f9ded2bdff225a9afc22f4f0565d32fab2a0a639f81dddd8f347523e","12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},
	/* 80 */
	{"$pbkdf2-hmac-sha512$10000.78783334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334.302c2f7f2a6366f4cc854aca7c74be3b5b7c2110c05d3a0700e51740b4fbb929a233e9fad8e36c6b7f8d80a3ede00dbef057a95ffef96a998f234d44c84608fd","12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
	/* 107 salt, 110 pw */
	{"$pbkdf2-hmac-sha512$10000.7878333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637.8e3b24e8dd572201c5294edb2605ce14acbd9645f616bb9b3be8e558d2ec2018fbb52df026fef71854cf0277e2a5adb3162e93c9e897e21368e5091f3a581598","12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},
	/* OS X 10.8 Mountain Lion hashes, "dave" format */
	{"$ml$23923$c3fa2e153466f7619286024fe7d812d0a8ae836295f84b9133ccc65456519fc3$ccb903ee691ade6d5dee9b3c6931ebed6ddbb1348f1b26c21add8ba0d45f27e61e97c0b80d9a18020944bb78f1ebda6fdd79c5cf08a12c80522caf987c287b6d", "openwall"},
	{"$ml$37174$ef768765ba15907760b71789fe62436e3584dfadbbf1eb8bf98673b60ff4e12b$294d42f6e0c3a93d598340bfb256efd630b53f32173c2b0d278eafab3753c10ec57b7d66e0fa79be3b80b3693e515cdd06e9e9d26d665b830159dcae152ad156", "m\xC3\xBCller"},
	{"$ml$24213$db9168b655339be3ff8936d2cf3cb573bdf7d40afd9a17fca439a0fae1375960$471a868524d66d995c6a8b7a0d27bbbc1af0c203f1ac31e7ceb2fde92f94997b887b38131ac2b543d285674dce639560997136c9af91916a2865ba960762196f", "applecrap"},
	{"$ml$37313$189dce2ede21e297a8884d0a33e4431107e3e40866f3c493e5f9506c2bd2fe44$948010870e110a6d185494799552d8cf30b0203c6706ab06e6270bf0ac17d496d820c5a75c12caf9070051f34acd2a2911bb38b202eebd4413e571e4fbff883e75f35c36c88a2b42a4fb521a97953438c72b2182fd9c5bba902395766e703b52b9aaa3895770d3cebffbee05076d9110ebb9f0342692a238174655b1acdce1c0", "crackable4us"},
//	/* max length password (and longer salt) made by pass_gen.pl */
//  {"$pbkdf2-hmac-sha512$56789.3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738.c4ac265e1b5d30694d04454e88f3f363a401aa82c7936d08d6bfc0751bc3e395b38422116665feecade927e7fa339d60022796f1354b064a4dc3c5304adf102a","12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345"},
	{NULL}
};

int pbkdf2_hmac_sha512_valid(char *ciphertext, struct fmt_main *self) {
	char *ptr, *ctcopy, *keeptr;
	size_t len;

	if (strncmp(ciphertext, PBKDF2_SHA512_FORMAT_TAG, PBKDF2_SHA512_TAG_LEN))
		return 0;
	if (strlen(ciphertext) > PBKDF2_SHA512_MAX_CIPHERTEXT_LENGTH)
		return 0;
	ciphertext += PBKDF2_SHA512_TAG_LEN;
	if (!(ctcopy = xstrdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	if (!(ptr = strtokm(ctcopy, ".")))
		goto error;
	if (!isdecu(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, ".")))
		goto error;
	len = strlen(ptr); // salt length
	if (len > 2 * PBKDF2_64_MAX_SALT_SIZE || len & 1)
		goto error;
	if (!ishex(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, ".")))
		goto error;
	len = strlen(ptr); // binary length
	if (len < PBKDF2_SHA512_BINARY_SIZE || len > PBKDF2_SHA512_MAX_BINARY_SIZE || len & 1)
		goto error;
	if (!ishex(ptr))
		goto error;
	ptr = strtokm(NULL, ".");
	if (ptr)
		goto error;
	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

char *pbkdf2_hmac_sha512_prepare(char *split_fields[10], struct fmt_main *self) {
	static char out[PBKDF2_SHA512_MAX_CIPHERTEXT_LENGTH + 1];
	int i;

	if (!*split_fields[1])
		return split_fields[1];

	/* Unify format */
	if (!strncmp(split_fields[1], PBKDF2_SHA512_FORMAT_TAG, PBKDF2_SHA512_TAG_LEN))
		i = PBKDF2_SHA512_TAG_LEN;
	else if (!strncmp(split_fields[1], FORMAT_TAG_ML, FORMAT_TAG_ML_LEN))
		i = FORMAT_TAG_ML_LEN;
	else if (!strncmp(split_fields[1], FORMAT_TAG_GRUB, FORMAT_TAG_GRUB_LEN))
		i = FORMAT_TAG_GRUB_LEN;
	else
		return split_fields[1];

	strcpy(out, PBKDF2_SHA512_FORMAT_TAG);
	strnzcpy(&out[PBKDF2_SHA512_TAG_LEN], &split_fields[1][i], sizeof(out)-PBKDF2_SHA512_TAG_LEN-1);

	if (!strncmp(split_fields[1], FORMAT_TAG_ML, FORMAT_TAG_ML_LEN))
		for (i = PBKDF2_SHA512_TAG_LEN+1; out[i]; i++)
			if (out[i] == '$')
				out[i] = '.';

	if (pbkdf2_hmac_sha512_valid(out, self))
		return out;
	else
		return split_fields[1];
}

char *pbkdf2_hmac_sha512_split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[PBKDF2_SHA512_MAX_CIPHERTEXT_LENGTH + 1];
	char *cp;

	strnzcpylwr(out, ciphertext, sizeof(out));
	if (*out == '$') {
		cp = strchr(&out[1], '$');
		if (cp) {
			++cp;
			cp = strchr(cp, '$');
			while (cp) {
				*cp = '.';
			}
		}
	}
	return out;
}

void *pbkdf2_hmac_sha512_binary(char *ciphertext) {
	static union {
		unsigned char c[PBKDF2_SHA512_BINARY_SIZE];
		uint64_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = strrchr(ciphertext, '.') + 1;
	for (i = 0; i < PBKDF2_SHA512_BINARY_SIZE && *p; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return out;
}

int pbkdf2_hmac_sha512_cmp_exact(char *key, char *source, unsigned char *salt, int length, int rounds)
{
	int i = 0, len, result;
	char *p;
	char delim;
	unsigned char *binary, *crypt;

	delim = strchr(source, '.') ? '.' : '$';
	p = strrchr(source, delim) + 1;
	len = strlen(p) / 2;

	if (len == PBKDF2_SHA512_BINARY_SIZE) return 1;

	binary = mem_alloc(len);
	crypt = mem_alloc(len);

	while (*p) {
		binary[i++] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	pbkdf2_sha512((const unsigned char *)key, strlen(key), salt, length, rounds, crypt, len, 0);
	result = !memcmp(binary, crypt, len);
	if (!result) {
		fprintf(stderr, "\npbkdf2-hmac-sha512: Warning: Partial match for '%s'   salt_len=%d rounds=%d bin_len=%d.\n"
		        "This is a bug or a malformed input line of:\n%s\n",
		        key, length, rounds, len, source);
		dump_hex("crypt results", crypt, len);
		dump_hex("salt hex     ", salt, length);
	}
	MEM_FREE(binary);
	MEM_FREE(crypt);
	return result;
}

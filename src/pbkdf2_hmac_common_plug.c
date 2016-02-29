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
#include "base64_convert.h"
#include "pbkdf2_hmac_common.h"
#define OPENCL_FORMAT
#define PBKDF2_HMAC_MD4_ALSO_INCLUDE_CTX 1
#include "pbkdf2_hmac_md4.h"
#define PBKDF2_HMAC_MD5_ALSO_INCLUDE_CTX 1
#include "pbkdf2_hmac_md5.h"
#define PBKDF2_HMAC_SHA1_ALSO_INCLUDE_CTX 1
#include "pbkdf2_hmac_sha1.h"

/**************************************
 * Common stuff for pbkdf2-md4 hashes
 **************************************/

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


/**************************************
 * Common stuff for pbkdf2-md5 hashes
 **************************************/

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
	int i;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < PBKDF2_MDx_BINARY_SIZE; i++) {
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


/**************************************
 * Common stuff for pbkdf2-sha1 hashes
 **************************************/

struct fmt_tests pbkdf2_hmac_sha1_common_tests[] = {
	{"$pbkdf2-hmac-sha1$1000.fd11cde0.27de197171e6d49fc5f55c9ef06c0d8751cd7250", "3956"},
	{"$pbkdf2-hmac-sha1$1000$6926d45e$231c561018a4cee662df7cd4a8206701c5806af9", "1234"},
	{"$pbkdf2-hmac-sha1$1000.98fcb0db.37082711ff503c2d2dea9a5cf7853437c274d32e", "5490"},
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
	{"$pbkdf2-hmac-sha1$1000.30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334.be2cfcaf566d4fcd45670b52fb0bd0372a0b9b2f", "password"},
	{"$pbkdf2-hmac-sha1$1000.3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031.c2dd966f13812d4c6012bfa9c0326b308e7a3dd5", "password"},
	{"$pbkdf2-hmac-sha1$1000.30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930.0743822bd75e509ce5ee4028d59fb0eaa00404a0", "password"},
	{"$pbkdf2-hmac-sha1$1000.303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839.48aac2e43431406af6fa08cb4ad23d98101bff04", "password"},
	{"$pbkdf2-hmac-sha1$1000.303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233.3a025719f3f4120d0172e56d504790916e0be397", "password"},
	{"$pbkdf2-hmac-sha1$1000.3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132.fae2eacc292606642bbf4eb74c35e18bc5f6297b", "password"},
	{"$pbkdf2-hmac-sha1$1000.30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031.c13037123928b5c895df01e2e371752d447495ca", "password"},
	{"$pbkdf2-hmac-sha1$1000.303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930.a145d99036ea8d7ec08b5b10b3fa2b5227482d16", "password"},
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
	if (!(ctcopy = strdup(ciphertext)))
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
	
	strnzcpy(out, ciphertext, sizeof(out));
	strlwr(out);
	cp = strchr(out, '.');
	while (cp) {
		*cp = '$';
		cp = strchr(cp, '.');
	}
	return out;
}

#define PKCS5S2_TAG                         "{PKCS5S2}"
#define PK5K2_TAG                           "$p5k2$"

char *pbkdf2_hmac_sha1_prepare(char *fields[10], struct fmt_main *self)
{
	static char Buf[PBKDF2_SHA1_MAX_CIPHERTEXT_LENGTH + 1];
	if (strncmp(fields[1], PKCS5S2_TAG, 9) != 0 && strncmp(fields[1], PK5K2_TAG, 6))
		return fields[1];
	if (!strncmp(fields[1], PKCS5S2_TAG, 9)) {
		char tmp[120+1];
		if (strlen(fields[1]) > 75) return fields[1];
		//{"{PKCS5S2}DQIXJU038u4P7FdsuFTY/+35bm41kfjZa57UrdxHp2Mu3qF2uy+ooD+jF5t1tb8J", "password"},
		//{"$pbkdf2-hmac-sha1$10000$0d0217254d37f2ee0fec576cb854d8ff$edf96e6e3591f8d96b9ed4addc47a7632edea176bb2fa8a03fa3179b75b5bf09", "password"},
		base64_convert(&(fields[1][9]), e_b64_mime, strlen(&(fields[1][9])), tmp, e_b64_hex, sizeof(tmp), 0);
		sprintf(Buf, "$pbkdf2-hmac-sha1$10000$%32.32s$%s", tmp, &tmp[32]);
		return Buf;
	}
	if (!strncmp(fields[1], PK5K2_TAG, 6)) {
		char tmps[160+1], tmph[160+1], *cp, *cp2;
		unsigned iter=0;
		// salt was listed as 1024 bytes max. But our max salt size is 64 bytes (~90 base64 bytes).
		if (strlen(fields[1]) > 128) return fields[1];
		//{"$p5k2$2710$oX9ZZOcNgYoAsYL-8bqxKg==$AU2JLf2rNxWoZxWxRCluY0u6h6c=", "password" },
		//{"$pbkdf2-hmac-sha1$10000$a17f5964e70d818a00b182fef1bab12a$014d892dfdab3715a86715b144296e634bba87a7", "password"},
		cp = fields[1];
		cp += 6;
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
		base64_convert(cp, e_b64_mime, cp2-cp, tmps, e_b64_hex, sizeof(tmps), flg_Base64_MIME_DASH_UNDER);
		if (strlen(tmps) > 64) return fields[1];
		++cp2;
		base64_convert(cp2, e_b64_mime, strlen(cp2), tmph, e_b64_hex, sizeof(tmph), flg_Base64_MIME_DASH_UNDER);
		if (strlen(tmph) != 40) return fields[1];
		sprintf(Buf, "$pbkdf2-hmac-sha1$%d$%s$%s", iter, tmps, tmph);
		return Buf;
	}
	return fields[1];
}

void *pbkdf2_hmac_sha1_binary(char *ciphertext) {
	static union {
		unsigned char c[PBKDF2_SHA1_BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < PBKDF2_SHA1_BINARY_SIZE; i++) {
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
#if !ARCH_LITTLE_ENDIAN
	for (i = 0; i < len/sizeof(uint32_t); ++i) {
		((uint32_t*)binary)[i] = JOHNSWAP(((uint32_t*)binary)[i]);
	}
#endif
	pbkdf2_sha1((const unsigned char*)key,
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
		fprintf(stderr, "\npbkdf2-hmac-sha1: Warning: Partial match for '%s'.\n"
		        "This is a bug or a malformed input line of:\n%s\n",
		        key, source);
	return result;
}

/**************************************
 * Common stuff for pbkdf2-sha256 hashes
 **************************************/
 #define FMT_CISCO8		"$8$"

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
	// cisco type 8 hashes.  20k iterations, different base-64 (same as WPA).  Also salt is used RAW, it is not base64 decoded prior to usage
	{"$8$dsYGNam3K1SIJO$7nv/35M/qr6t.dVc7UY9zrJDWRVqncHub1PE9UlMQFs", "cisco"},
	{"$8$6NHinlEjiwvb5J$RjC.H.ydVb34wDLqJvfjyG1ubxYKpfXqv.Ry9mtrNBY", "password"},
	{"$8$lGO8juTOQLPCHw$cBv2WEaFCLUA24Z48CKUGixIywyGFP78r/slQcMXr3M", "JtR"},
	{NULL}
};

int pbkdf2_hmac_sha256_valid(char *ciphertext, struct fmt_main *self) {
	int saltlen = 0;
	char *p, *c = ciphertext;

	if (strncmp(ciphertext, FMT_CISCO8, 3) == 0) {
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
	saltlen = base64_valid_length(c, e_b64_mime, flg_Base64_MIME_PLUS_TO_DOT);
	c += saltlen;
	saltlen = B64_TO_RAW_LEN(saltlen);
	if (saltlen > PBKDF2_32_MAX_SALT_SIZE)
		return 0;
	if (*c != '$') return 0;
	c++;
	if (base64_valid_length(c, e_b64_mime, flg_Base64_MIME_PLUS_TO_DOT) != 43)
		return 0;
	return 1;
}

char *pbkdf2_hmac_sha256_prepare(char *fields[10], struct fmt_main *self) {
	static char Buf[PBKDF2_SHA256_MAX_CIPHERTEXT_LENGTH + 1];
	char tmp[43+1], *cp;

	if (strncmp(fields[1], FMT_CISCO8, 3) != 0)
		return fields[1];
	if (strlen(fields[1]) != 4+14+43)
		return fields[1];
	sprintf (Buf, "%s20000$%14.14s$%s", PBKDF2_SHA256_FORMAT_TAG, &(fields[1][3]),
		base64_convert_cp(&(fields[1][3+14+1]), e_b64_crypt, 43, tmp, e_b64_mime, sizeof(tmp), flg_Base64_NO_FLAGS));
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
		ARCH_WORD dummy;
	} buf;
	char *ret = buf.c;
	char *c = ciphertext;
	c += PBKDF2_SHA256_TAG_LEN;
	c = strchr(c, '$') + 1;
	c = strchr(c, '$') + 1;
#ifdef DEBUG
	assert(strlen(c) == 43);
#endif
	base64_convert(c, e_b64_mime, 43, buf.c, e_b64_raw, sizeof(buf.c), flg_Base64_MIME_PLUS_TO_DOT);
	return ret;
}

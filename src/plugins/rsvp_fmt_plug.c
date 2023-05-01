/*
 * Cracker for HMAC-MD5 and HMAC-SHA1 based authentication in RSVP.
 *
 * This software is Copyright (c) 2014 Dhiru Kholia <dhiru at openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without#
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rsvp;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rsvp);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#ifdef __MIC__
#define OMP_SCALE               4096
#endif
#ifndef OMP_SCALE
#define OMP_SCALE               32  // MKPC and OMP_SCALE hand-tuned on Core i5-6500
#endif

#include "arch.h"
#include "md5.h"
#include "sha.h"
#include "sha2.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "params.h"
#include "options.h"

#define FORMAT_LABEL            "rsvp"
#define FORMAT_NAME             "HMAC-MD5 / HMAC-SHA1, RSVP, IS-IS, OMAPI, RNDC, TSIG"
#define FORMAT_TAG              "$rsvp$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "MD5 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             16
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(int)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      32
#define HEXCHARS                "0123456789abcdef"
#define MAX_SALT_SIZE           8192
// Currently only 6 types are supported (1 for md5, 2 for SHA1, 3 for SHA224,
// and so on). Bump this number each type a type is added, and make sure the
// types are sequential.
#define MAX_TYPES               6

static struct fmt_tests tests[] = {
	{"$rsvp$1$10010000ff0000ac002404010100000000000001d7e95bfa0000003a00000000000000000000000000000000000c0101c0a8011406000017000c0301c0a8010a020004020008050100007530000c0b01c0a8010a0000000000240c0200000007010000067f00000545fa000046fa000045fa0000000000007fffffff00300d020000000a010000080400000100000001060000014998968008000001000000000a000001000005dc05000000$636d8e6db5351fbc9dad620c5ec16c0b", "password12345"},
	{"$rsvp$2$10010000ff0000b0002804010100000000000001d7e95bfa0000055d0000000000000000000000000000000000000000000c0101c0a8011406000017000c0301c0a8010a020004020008050100007530000c0b01c0a8010a0000000000240c0200000007010000067f00000545fa000046fa000045fa0000000000007fffffff00300d020000000a010000080400000100000001060000014998968008000001000000000a000001000005dc05000000$ab63f157e601742983b853f13a63bc4d4379a434", "JtR_kicks_ass"},
	// IS-IS HMAC-MD5 hash
	{"$rsvp$1$831b01000f01000001192168001005001e05d940192168001005010a1136000000000000000000000000000000008101cc0104034900018404c0a87805d30300000008ff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008ff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008ff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008ff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008ff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000890000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000$ae116a4cff88a4b13b3ae14bf169ff5c", "password12345"},
	// IS-IS HMAC-MD5 hash
	{"$rsvp$1$831b01000f01000001192168001005001e05d940192168001005010a1136000000000000000000000000000000008101cc0104034900018404c0a87805d30300000008ff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008ff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008ff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008ff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008ff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000890000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000$5048a1fe4ed87c32bc6c4af43095cae4", "1234567890"},
	// IS-IS HMAC-MD5, isis-hmac-md5_key-1234.pcap
	{"$rsvp$1$831401001101000301192168201101001b005a000104034900018102cc8ee50400000002e810fe800000000000000465fffffe000000f00f0000000004192168201104000000040a113600000000000000000000000000000000$44b62860b363f9adf60acdb9d66abe27", "1234"},
	// DHCP OMAPI hash
	{"$rsvp$1$0000001000000001000000004e878f6e000000000006637265617465000000040000000100096578636c7573697665000000040000000100047479706500000004686f737400000000$6240c96047e5e0a6da897f0e19dda707", "12345678"},
	// BIND RNDC hmac-md5 hash
	{"$rsvp$1$055f6374726c0200000038045f7365720100000006343336393532045f74696d010000000a31353132373936343538045f657870010000000a31353132373936353138055f64617461020000000e047479706501000000046e756c6c$84bf81fdcb5113dfb9a1b02c32091b10", "12345678"},
	// BIND RNDC hmac-sha1 hash
	{"$rsvp$2$055f6374726c0200000039045f736572010000000731343030373138045f74696d010000000a31353132383031313735045f657870010000000a31353132383031323335055f64617461020000000e047479706501000000046e756c6c$bdcdde831ef62d4db001155d0d4b71073b9f3e46", "12345678"},
	// BIND RNDC hmac-sha224 hash
	{"$rsvp$3$055f6374726c020000003a045f73657201000000083130353433393138045f74696d010000000a31353132383035323538045f657870010000000a31353132383035333138055f64617461020000000e047479706501000000046e756c6c$34e0b7c5f737a800b684196374249eb2e1ab26f08be8ef967541cb0e", "12345678"},
	// BIND RNDC hmac-sha256 hash
	{"$rsvp$4$055f6374726c0200000039045f736572010000000738363630353334045f74696d010000000a31353132383031323633045f657870010000000a31353132383031333233055f64617461020000000e047479706501000000046e756c6c$90998313a5c554cc373bdef4157e23a51655ce55e0dd258049d7bedf2497bb78", "12345678"},
	// BIND RNDC hmac-sha384 hash
	{"$rsvp$5$055f6374726c020000003a045f73657201000000083133373633393733045f74696d010000000a31353132383035343931045f657870010000000a31353132383035353531055f64617461020000000e047479706501000000046e756c6c$7009d9833402cfd59045bb877addac39357827eadd01059b27507d73846a80b2c1bb8407154fdbcbef1fa6412e7ce6c2", "12345678"},
	// BIND RND hmac-sha512 hash
	{"$rsvp$6$055f6374726c0200000039045f736572010000000734343131323530045f74696d010000000a31353132383033353139045f657870010000000a31353132383033353739055f64617461020000000e047479706501000000046e756c6c$8de37f5b8fee6733bf0edf895ad2751989f7a6317534216a16db68f55c853d15f1114fe3c0f98521c1dcaa29eabe1d603cc2a3fee7f9dc22f127dfa220b5c632", "12345678"},
	// BIND TSIG request
	{"$rsvp$1$b75828000001000000010000076578616d706c6503636f6d000006000109737562646f6d61696ec00c000100010000003c00047f0000010a7570646174652d6b65790000ff0000000008686d61632d6d6435077369672d616c670372656703696e740000005a98d820012c00000000$43fa86cc6e26e83c495e9ee4bc5662a1", "openwall"},
	// BIND TSIG request
	{"$rsvp$1$dfd628000001000000010000076578616d706c6503636f6d000006000109737562646f6d61696ec00c000100010000003c00047f0000010a7570646174652d6b65790000ff0000000008686d61632d6d6435077369672d616c670372656703696e740000005a98d537012c00000000$e2cda818e19c70bf9779f2b9ac08891e", "12345678"},
	// BIND TSIG request
	{"$rsvp$1$4e6528000001000000010000076578616d706c6503636f6d000006000109737562646f6d61696ec00c000100010000003c00047f0000010a7570646174652d6b65790000ff0000000008686d61632d6d6435077369672d616c670372656703696e740000005a38f8bf012c00000000$62baf26f68deab15ebc6f4c456533841", "12345678"},
	// BIND TSIG response
	{"$rsvp$1$001062baf26f68deab15ebc6f4c4565338414e65a8820001000000000000076578616d706c6503636f6d00000600010a7570646174652d6b65790000ff0000000008686d61632d6d6435077369672d616c670372656703696e740000005a38f8c7012c00000000$867b3d04d7793a538509d8dd96f66bc2", "12345678"},
	// BIND TSIG, HMAC-SHA1
	{"$rsvp$2$a4d428000001000000010000076578616d706c6503636f6d000006000109737562646f6d61696ec00c000100010000003c00047f0000010a7570646174652d6b65790000ff0000000009686d61632d736861310000005a98fdec012c00000000$8a6bf3af6856c77c904dbdcd4f4b87d40262c5e3", "12345678"},
	// BIND TSIG, HMAC-SHA512
	{"$rsvp$6$41c528000001000000010000076578616d706c6503636f6d000006000109737562646f6d61696ec00c000100010000003c00047f0000010a7570646174652d6b65790000ff000000000b686d61632d7368613531320000005a98feab012c00000000$20da0f6c32b5424bab49ff62790f0e2c56dcfb8a8d9787f03882dc37acd902574c46f11cf1d743f066e6c451e770c7206c2cd7738244ea19d63741777acefbfd", "12345678"},
	// BIND TSIG, HMAC-SHA256
	{"$rsvp$4$e23828000001000000010000076578616d706c6503636f6d000006000109737562646f6d61696ec00c000100010000003c00047f0000010a7570646174652d6b65790000ff000000000b686d61632d7368613235360000005a98ff1b012c00000000$6a9122e0e5220fdaa48836a444a5fbbe21c23a36cb04d6f3e9d6a8d4737e3886", "äbc"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;

// When we add more types, they need to be sequential (next will be 7),
// AND we need to bump this to the count. Each type will use one of these
// to track whether it has build the first half of the hmac. The size
// of this array should be 1 more than the max number of types.
static int new_keys[MAX_TYPES+1];

// We make our crypt_out large enough for an SHA512 output now. Even though
// we only compare first BINARY_SIZE data.
static uint32_t (*crypt_out)[64 / sizeof(uint32_t)];
static SHA_CTX *ipad_ctx;
static SHA_CTX *opad_ctx;
static SHA256_CTX *ipad_ctx_224;
static SHA256_CTX *opad_ctx_224;
static SHA256_CTX *ipad_ctx_256;
static SHA256_CTX *opad_ctx_256;
static SHA512_CTX *ipad_ctx_384;
static SHA512_CTX *opad_ctx_384;
static SHA512_CTX *ipad_ctx_512;
static SHA512_CTX *opad_ctx_512;
static MD5_CTX *ipad_mctx;
static MD5_CTX *opad_mctx;

static const char *ipad_constant_block = "\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36";

static const char *opad_constant_block = "\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C";

static  struct custom_salt {
	int type;
	int salt_length;
	unsigned char salt[MAX_SALT_SIZE];
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
	ipad_ctx = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*ipad_ctx));
	opad_ctx = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*opad_ctx));
	ipad_ctx_224 = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*ipad_ctx_224));
	opad_ctx_224 = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*opad_ctx_224));
	ipad_ctx_256 = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*ipad_ctx_256));
	opad_ctx_256 = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*opad_ctx_256));
	ipad_ctx_384 = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*ipad_ctx_384));
	opad_ctx_384 = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*opad_ctx_384));
	ipad_ctx_512 = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*ipad_ctx_512));
	opad_ctx_512 = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*opad_ctx_512));
	ipad_mctx = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*ipad_mctx));
	opad_mctx = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*opad_mctx));
}

static void done(void)
{
	MEM_FREE(opad_mctx);
	MEM_FREE(ipad_mctx);
	MEM_FREE(opad_ctx);
	MEM_FREE(ipad_ctx);
	MEM_FREE(opad_ctx_224);
	MEM_FREE(ipad_ctx_224);
	MEM_FREE(opad_ctx_256);
	MEM_FREE(ipad_ctx_256);
	MEM_FREE(opad_ctx_384);
	MEM_FREE(ipad_ctx_384);
	MEM_FREE(opad_ctx_512);
	MEM_FREE(ipad_ctx_512);
	MEM_FREE(crypt_out);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *strkeep;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return 0;

	strkeep = xstrdup(ciphertext);
	p = &strkeep[TAG_LENGTH];

	if ((p = strtokm(p, "$")) == NULL) /* version */
		goto err;
	if (p[0] < '1' || p[0] > '6' || p[1])
		goto err;

	if ((p = strtokm(NULL, "$")) == NULL) /* salt */
		goto err;
	if (strlen(p) >= MAX_SALT_SIZE*2)
		goto err;
	if (!ishexlc(p))
		goto err;

	if ((p = strtokm(NULL, "$")) == NULL) /* hash */
		goto err;
	/* There is code in get_binary() that trims longer binary values, so we do not need to check for extra long inputs */
	if (strlen(p) < BINARY_SIZE*2)
		goto err;
	if (!ishexlc(p))
		goto err;

	MEM_FREE(strkeep);
	return 1;
err:;
	MEM_FREE(strkeep);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i;
	char *p, *q;

	memset(&cs, 0, SALT_SIZE);
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	p = ciphertext;
	cs.type = atoi(p);
	p = p + 2;
	q = strchr(p, '$') + 1;
	cs.salt_length = (q - p) / 2;

	for (i = 0; i < cs.salt_length; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) |
			atoi16[ARCH_INDEX(p[2 * i + 1])];

	return (void*)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char buf[64];

		if (cur_salt->type == 1) {
			MD5_CTX ctx;
			if (new_keys[cur_salt->type]) {
				int i, len = strlen(saved_key[index]);
				unsigned char *p = (unsigned char*)saved_key[index];
				unsigned char pad[64];

				if (len > 64) {
					MD5_Init(&ctx);
					MD5_Update(&ctx, p, len);
					MD5_Final(buf, &ctx);
					len = 16;
					p = buf;
				}
				for (i = 0; i < len; ++i) {
					pad[i] = p[i] ^ 0x36;
				}
				MD5_Init(&ipad_mctx[index]);
				MD5_Update(&ipad_mctx[index], pad, len);
				if (len < 64)
					MD5_Update(&ipad_mctx[index], ipad_constant_block, 64-len);
				for (i = 0; i < len; ++i) {
					pad[i] = p[i] ^ 0x5C;
				}
				MD5_Init(&opad_mctx[index]);
				MD5_Update(&opad_mctx[index], pad, len);
				if (len < 64)
					MD5_Update(&opad_mctx[index], opad_constant_block, 64-len);
			}
			memcpy(&ctx, &ipad_mctx[index], sizeof(ctx));
			MD5_Update(&ctx, cur_salt->salt, cur_salt->salt_length);
			MD5_Final(buf, &ctx);
			memcpy(&ctx, &opad_mctx[index], sizeof(ctx));
			MD5_Update(&ctx, buf, 16);
			MD5_Final((unsigned char*)(crypt_out[index]), &ctx);
		} else if (cur_salt->type == 2) {
			SHA_CTX ctx;

			if (new_keys[cur_salt->type]) {
				int i, len = strlen(saved_key[index]);
				unsigned char *p = (unsigned char*)saved_key[index];
				unsigned char pad[64];

				if (len > 64) {
					SHA1_Init(&ctx);
					SHA1_Update(&ctx, p, len);
					SHA1_Final(buf, &ctx);
					len = 20;
					p = buf;
				}
				for (i = 0; i < len; ++i) {
					pad[i] = p[i] ^ 0x36;
				}
				SHA1_Init(&ipad_ctx[index]);
				SHA1_Update(&ipad_ctx[index], pad, len);
				if (len < 64)
					SHA1_Update(&ipad_ctx[index], ipad_constant_block, 64-len);
				for (i = 0; i < len; ++i) {
					pad[i] = p[i] ^ 0x5C;
				}
				SHA1_Init(&opad_ctx[index]);
				SHA1_Update(&opad_ctx[index], pad, len);
				if (len < 64)
					SHA1_Update(&opad_ctx[index], opad_constant_block, 64-len);
			}
			memcpy(&ctx, &ipad_ctx[index], sizeof(ctx));
			SHA1_Update(&ctx, cur_salt->salt, cur_salt->salt_length);
			SHA1_Final(buf, &ctx);
			memcpy(&ctx, &opad_ctx[index], sizeof(ctx));
			SHA1_Update(&ctx, buf, 20);
			// NOTE, this writes 20 bytes. That is why we had to bump up the size of each crypt_out[] value,
			// even though we only look at the first 16 bytes when comparing the saved binary.
			SHA1_Final((unsigned char*)(crypt_out[index]), &ctx);
		} else if (cur_salt->type == 3) {
			SHA256_CTX ctx;

			if (new_keys[cur_salt->type]) {
				int i, len = strlen(saved_key[index]);
				unsigned char *p = (unsigned char*)saved_key[index];
				unsigned char pad[64];

				if (len > 64) {
					SHA224_Init(&ctx);
					SHA224_Update(&ctx, p, len);
					SHA224_Final(buf, &ctx);
					len = 28;
					p = buf;
				}
				for (i = 0; i < len; ++i) {
					pad[i] = p[i] ^ 0x36;
				}
				SHA224_Init(&ipad_ctx_224[index]);
				SHA224_Update(&ipad_ctx_224[index], pad, len);
				if (len < 64)
					SHA224_Update(&ipad_ctx_224[index], ipad_constant_block, 64-len);
				for (i = 0; i < len; ++i) {
					pad[i] = p[i] ^ 0x5C;
				}
				SHA224_Init(&opad_ctx_224[index]);
				SHA224_Update(&opad_ctx_224[index], pad, len);
				if (len < 64)
					SHA224_Update(&opad_ctx_224[index], opad_constant_block, 64-len);
			}
			memcpy(&ctx, &ipad_ctx_224[index], sizeof(ctx));
			SHA224_Update(&ctx, cur_salt->salt, cur_salt->salt_length);
			SHA224_Final(buf, &ctx);
			memcpy(&ctx, &opad_ctx_224[index], sizeof(ctx));
			SHA224_Update(&ctx, buf, 28);
			SHA224_Final((unsigned char*)(crypt_out[index]), &ctx);
		} else if (cur_salt->type == 4) {
			SHA256_CTX ctx;

			if (new_keys[cur_salt->type]) {
				int i, len = strlen(saved_key[index]);
				unsigned char *p = (unsigned char*)saved_key[index];
				unsigned char pad[64];

				if (len > 64) {
					SHA256_Init(&ctx);
					SHA256_Update(&ctx, p, len);
					SHA256_Final(buf, &ctx);
					len = 32;
					p = buf;
				}
				for (i = 0; i < len; ++i) {
					pad[i] = p[i] ^ 0x36;
				}
				SHA256_Init(&ipad_ctx_256[index]);
				SHA256_Update(&ipad_ctx_256[index], pad, len);
				if (len < 64)
					SHA256_Update(&ipad_ctx_256[index], ipad_constant_block, 64-len);
				for (i = 0; i < len; ++i) {
					pad[i] = p[i] ^ 0x5C;
				}
				SHA256_Init(&opad_ctx_256[index]);
				SHA256_Update(&opad_ctx_256[index], pad, len);
				if (len < 64)
					SHA256_Update(&opad_ctx_256[index], opad_constant_block, 64-len);
			}
			memcpy(&ctx, &ipad_ctx_256[index], sizeof(ctx));
			SHA256_Update(&ctx, cur_salt->salt, cur_salt->salt_length);
			SHA256_Final(buf, &ctx);
			memcpy(&ctx, &opad_ctx_256[index], sizeof(ctx));
			SHA256_Update(&ctx, buf, 32);
			SHA256_Final((unsigned char*)(crypt_out[index]), &ctx);
		} else if (cur_salt->type == 5) {
			SHA512_CTX ctx;

			if (new_keys[cur_salt->type]) {
				int i, len = strlen(saved_key[index]);
				unsigned char *p = (unsigned char*)saved_key[index];
				unsigned char pad[128];

				if (len > 128) {
					SHA384_Init(&ctx);
					SHA384_Update(&ctx, p, len);
					SHA384_Final(buf, &ctx);
					len = 48;
					p = buf;
				}
				for (i = 0; i < len; ++i) {
					pad[i] = p[i] ^ 0x36;
				}
				SHA384_Init(&ipad_ctx_384[index]);
				SHA384_Update(&ipad_ctx_384[index], pad, len);
				if (len < 128)
					SHA384_Update(&ipad_ctx_384[index], ipad_constant_block, 128-len);
				for (i = 0; i < len; ++i) {
					pad[i] = p[i] ^ 0x5C;
				}
				SHA384_Init(&opad_ctx_384[index]);
				SHA384_Update(&opad_ctx_384[index], pad, len);
				if (len < 128)
					SHA384_Update(&opad_ctx_384[index], opad_constant_block, 128-len);
			}
			memcpy(&ctx, &ipad_ctx_384[index], sizeof(ctx));
			SHA384_Update(&ctx, cur_salt->salt, cur_salt->salt_length);
			SHA384_Final(buf, &ctx);
			memcpy(&ctx, &opad_ctx_384[index], sizeof(ctx));
			SHA384_Update(&ctx, buf, 48);
			SHA384_Final((unsigned char*)(crypt_out[index]), &ctx);
		} else if (cur_salt->type == 6) {
			SHA512_CTX ctx;

			if (new_keys[cur_salt->type]) {
				int i, len = strlen(saved_key[index]);
				unsigned char *p = (unsigned char*)saved_key[index];
				unsigned char pad[128];

				if (len > 128) {
					SHA512_Init(&ctx);
					SHA512_Update(&ctx, p, len);
					SHA512_Final(buf, &ctx);
					len = 64;
					p = buf;
				}
				for (i = 0; i < len; ++i) {
					pad[i] = p[i] ^ 0x36;
				}
				SHA512_Init(&ipad_ctx_512[index]);
				SHA512_Update(&ipad_ctx_512[index], pad, len);
				if (len < 128)
					SHA512_Update(&ipad_ctx_512[index], ipad_constant_block, 128-len);
				for (i = 0; i < len; ++i) {
					pad[i] = p[i] ^ 0x5C;
				}
				SHA512_Init(&opad_ctx_512[index]);
				SHA512_Update(&opad_ctx_512[index], pad, len);
				if (len < 128)
					SHA512_Update(&opad_ctx_512[index], opad_constant_block, 128-len);
			}
			memcpy(&ctx, &ipad_ctx_512[index], sizeof(ctx));
			SHA512_Update(&ctx, cur_salt->salt, cur_salt->salt_length);
			SHA512_Final(buf, &ctx);
			memcpy(&ctx, &opad_ctx_512[index], sizeof(ctx));
			SHA512_Update(&ctx, buf, 64);
			SHA512_Final((unsigned char*)(crypt_out[index]), &ctx);
		}
	}
	new_keys[cur_salt->type] = 0;

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (((uint32_t*)binary)[0] == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void rsvp_set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));

	// Workaround for self-test code not working as IRL
	new_keys[1] = new_keys[2] = new_keys[3] = new_keys[4] = new_keys[5] = new_keys[6] = 2;
}

static void clear_keys(void) {
	int i;
	for (i = 0; i <= MAX_TYPES; ++i)
		new_keys[i] = 1;
}

static char *get_key(int index)
{
	return saved_key[index];
}

// Report hash algorithm used for hmac as "tunable cost"
static unsigned int rsvp_hash_type(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->type;
}

struct fmt_main fmt_rsvp = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{
			"hash algorithm used for hmac [1:MD5 2:SHA1 3:SHA224 4:SHA256 5:SHA384 6:SHA512]"
		},
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			rsvp_hash_type,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		rsvp_set_key,
		get_key,
		clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif

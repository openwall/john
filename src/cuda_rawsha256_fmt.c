/*
* This software is Copyright (c) 2011-2012 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* This file is shared by raw-sha224-cuda and raw-sha256-cuda formats,
* SHA256 definition is used to distinguish between them.
*/
#ifdef HAVE_CUDA
#include <string.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_common.h"
#include "cuda_rawsha256.h"
#include "memdbg.h"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1	/// Raw benchmark
#define PLAINTEXT_LENGTH	19
#define SALT_SIZE		0

#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

#define FORMAT_NAME		""

#define TAG_LEN			(sizeof(FORMAT_TAG) - 1)

#ifdef SHA256
#define FORMAT_LABEL		"Raw-SHA256-cuda"
#define FORMAT_TAG		"$SHA256$"
#define ALGORITHM_NAME		"SHA256 CUDA (inefficient, development use mostly)"
#define CIPHERTEXT_LENGTH	64	///256bit
#define BINARY_SIZE		32
#define BINARY_ALIGN		MEM_ALIGN_WORD
#define SALT_ALIGN			1
#define SHA_HASH		sha256_hash
#define TESTS			sha256_tests
#define FMT_MAIN		fmt_cuda_rawsha256

static struct fmt_tests sha256_tests[] = {
	{"71c3f65d17745f05235570f1799d75e69795d469d9fcb83e326f82f1afa80dea", "epixoip"},
	{FORMAT_TAG "71c3f65d17745f05235570f1799d75e69795d469d9fcb83e326f82f1afa80dea", "epixoip"},
	{"25b64f637b373d33a8aa2b7579784e99a20e6b7dfea99a71af124394b8958f27", "doesthiswork"},
	{"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "password"},
	{"27c6794c8aa2f70f5f6dc93d3bfb25ca6de9b0752c8318614cbd4ad203bea24c", "ALLCAPS"},
	{"04cdd6c523673bf448efe055711a9b184817d7843b0a76c2046f5398b5854152", "TestTESTt3st"},
	{FORMAT_TAG "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f", "12345678"},
	{FORMAT_TAG "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ""},
	{FORMAT_TAG "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", ""},
#if 0
	{"LcV6aBcc/53FoCJjXQMd7rBUDEpeevrK8V5jQVoJEhU", "password"},
	{"$cisco4$LcV6aBcc/53FoCJjXQMd7rBUDEpeevrK8V5jQVoJEhU", "password"},
#endif
	{"a49c2c9d0c006c8cb55a9a7a38822b83e0cd442614cb416af952fa50156761dc", "openwall"},
	{"9e7d3e56996c5a06a6a378567e62f5aa7138ebb0f55c0bdaf73666bf77f73380", "mot\xf6rhead"},
#ifdef DEBUG
	{"c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646", "1234567890"},
#if 0
	{"$cisco4$OsOmQzwozC4ROs/CzpczJoShdCeW9lp7k/tGrPS5Kog", "1"},
	{"$cisco4$d7kgbEk.P6mpKdduC66fUy1BF0MImo3eyJ9uI/JbMRk", "openwall"},
	{"$cisco4$p5BSCWNS3ivUDpZlWthR.k4Q/xWqlFyEqXdaPikHenI", "2"},
	{"$cisco4$HwUf7ev9Fx84X2vvspULAeDbmwlg9jgm/Wk63kc3vfU", "11"},
	{"$cisco4$bsPEUMVATKKO9yeUlJfE3OCzHlgf0s6goJpg3P1k0UU", "test"},
	{"$cisco4$Xq81UiuCj7bz9B..EX2BZumsU/d8pF5gs2NlRMW6sTk", "applesucks"},
	{"$cisco4$O/D/cn1nawcByQoJfBxrNnUx6jjfWV.FNFx5TzmzihU", "AppleSucks"},
#endif
#if PLAINTEXT_LENGTH >19
	{"6ed645ef0e1abea1bf1e4e935ff04f9e18d39812387f63cda3415b46240f0405", "12345678901234567890"},
	{"f54e5c8f810648e7638d25eb7ed6d24b7e5999d588e88826f2aa837d2ee52ecd", "123456789012345678901234567890"},
	{"a4ebdd541454b84cc670c9f1f5508baf67ffd3fe59b883267808781f992a0b1d", "1234567890123456789012345678901234567890"},
	{"f58fffba129aa67ec63bf12571a42977c0b785d3b2a93cc0538557c91da2115d", "12345678901234567890123456789012345678901234567890"},
	{"3874d5c9cc5ab726e6bbebadee22c680ce530004d4f0bb32f765d42a0a6c6dc1", "123456789012345678901234567890123456789012345678901"},
	{"03c3a70e99ed5eeccd80f73771fcf1ece643d939d9ecc76f25544b0233f708e9", "1234567890123456789012345678901234567890123456789012345"},
	{"0f46e4b0802fee6fed599682a16287d0397699cfd742025482c086a70979e56a", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 31
	{"c62e4615bd39e222572f3a1bf7c2132ea1e65b17ec805047bd6b2842c593493f", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 32
	{"d5e285683cd4efc02d021a5c62014694958901005d6f71e89e0989fac77e4072", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 55
#if 0
	{"$cisco4$hUsuWZSE8dZERUBYNwRK8Aa8VxEGIHsuZFUCjNj2.Ac", "verylongbutweakpassword"},
	{"$cisco4$fLUL1VG98zYDf9Q.M40nZ5blVT3M6UBex74Blw.UDCc", "thismaximumpasswordlength"},
#endif
#endif
#endif
	{NULL}
};
#endif
#ifdef SHA224
#define FORMAT_LABEL		"Raw-SHA224-cuda"
#define FORMAT_TAG		"$SHA224$"
#define ALGORITHM_NAME		"SHA224 CUDA (inefficient, development use mostly)"
#define CIPHERTEXT_LENGTH	56	///224bit
#define BINARY_SIZE		28
#define BINARY_ALIGN		MEM_ALIGN_WORD
#define SALT_ALIGN		1
#define SHA_HASH 		sha224_hash
#define TESTS			sha224_tests
#define FMT_MAIN		fmt_cuda_rawsha224
static struct fmt_tests sha224_tests[] = {
	{"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01", "password"},
	{FORMAT_TAG "7e6a4309ddf6e8866679f61ace4f621b0e3455ebac2e831a60f13cd1", "12345678"},
	{FORMAT_TAG "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", ""},
	{"d6d8ff02342ea04cf65f8ab446b22c4064984c29fe86f858360d0319", "openwall"},
	{FORMAT_TAG "d6d8ff02342ea04cf65f8ab446b22c4064984c29fe86f858360d0319", "openwall"},
	{NULL}
};
#endif

extern void gpu_rawsha256(sha256_password *, SHA_HASH *, int);
extern void gpu_rawsha224(sha256_password *, SHA_HASH *, int);
extern void *cuda_pageLockedMalloc(void *, unsigned int);
extern void cuda_pageLockedFree(void *);
extern int cuda_getAsyncEngineCount();

static sha256_password *inbuffer;			/** binary ciphertexts **/
static SHA_HASH *outbuffer;				/** calculated hashes **/
static int overlap;
static void done(void)
{
	if (overlap) {
		cuda_pageLockedFree(inbuffer);
		cuda_pageLockedFree(outbuffer);
	} else {
		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
	}
}

static void init(struct fmt_main *self)
{
	cuda_init();
	if (cuda_getAsyncEngineCount() > 0) {
		overlap = 1;
		inbuffer =
		    cuda_pageLockedMalloc(inbuffer,
		    sizeof(sha256_password) * MAX_KEYS_PER_CRYPT);
		outbuffer =
		    cuda_pageLockedMalloc(outbuffer,
		    sizeof(SHA_HASH) * MAX_KEYS_PER_CRYPT);
	} else {
		overlap = 0;
		//device does not support overlapping memcpy and kernel execution
		inbuffer =
			(sha256_password *) mem_calloc(MAX_KEYS_PER_CRYPT,
			                               sizeof(sha256_password));
		outbuffer =
		    (SHA_HASH *) mem_alloc(MAX_KEYS_PER_CRYPT * sizeof(SHA_HASH));
	}
	check_mem_allocation(inbuffer, outbuffer);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	int i;
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LEN))
		ciphertext += TAG_LEN;
	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;
	for (i = 0; i < CIPHERTEXT_LENGTH; i++) {
		if (!((ciphertext[i] >= '0' && ciphertext[i] <= '9') ||
			(ciphertext[i] >= 'a' && ciphertext[i] <= 'f') ||
			(ciphertext[i] >= 'A' && ciphertext[i] <= 'Z')))
			return 0;
	}
	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LEN + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LEN))
		ciphertext += TAG_LEN;

	memcpy(out, FORMAT_TAG, TAG_LEN);
	memcpy(out + TAG_LEN, ciphertext, CIPHERTEXT_LENGTH + 1);
	strlwr(out + TAG_LEN);
	return out;
}

static void *get_binary(char *ciphertext)
{
	static char realcipher[BINARY_SIZE];
	int i;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LEN))
		ciphertext += TAG_LEN;
	memset(realcipher, 0, BINARY_SIZE);
	for (i = 0; i < BINARY_SIZE; i += 4) {
		realcipher[i] =
		    atoi16[ARCH_INDEX(ciphertext[(i + 3) * 2])] * 16 +
		    atoi16[ARCH_INDEX(ciphertext[(i + 3) * 2 + 1])];
		realcipher[i + 1] =
		    atoi16[ARCH_INDEX(ciphertext[(i + 2) * 2])] * 16 +
		    atoi16[ARCH_INDEX(ciphertext[(i + 2) * 2 + 1])];
		realcipher[i + 2] =
		    atoi16[ARCH_INDEX(ciphertext[(i + 1) * 2])] * 16 +
		    atoi16[ARCH_INDEX(ciphertext[(i + 1) * 2 + 1])];
		realcipher[i + 3] =
		    atoi16[ARCH_INDEX(ciphertext[(i) * 2])] * 16 +
		    atoi16[ARCH_INDEX(ciphertext[(i) * 2 + 1])];
	}
	return (void *) realcipher;
}

static void set_key(char *key, int index)
{
	memset(inbuffer[index].v, 0, PLAINTEXT_LENGTH);
	memcpy(inbuffer[index].v, key, PLAINTEXT_LENGTH);
	inbuffer[index].length = strlen(key);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, inbuffer[index].v, inbuffer[index].length);
	ret[inbuffer[index].length] = 0;
	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
#ifdef SHA256
	gpu_rawsha256(inbuffer, outbuffer, overlap);
#else
	gpu_rawsha224(inbuffer, outbuffer, overlap);
#endif
        return count;
}

static int get_hash_0(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xf;
}

static int get_hash_1(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xff;
}

static int get_hash_2(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xfff;
}

static int get_hash_3(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xffff;
}

static int get_hash_4(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xfffff;
}

static int get_hash_5(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xffffff;
}

static int get_hash_6(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0x7ffffff;
}

static int cmp_all(void *binary, int count)
{
	uint32_t i;
	uint32_t b = ((uint32_t *) binary)[0];
	for (i = 0; i < count; i++)
		if (b == outbuffer[i].v[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	int i;
	uint32_t *t = (uint32_t *) binary;
	for (i = 0; i < CIPHERTEXT_LENGTH / 8; i++)
		if (t[i] != outbuffer[index].v[i])
			return 0;
	return 1;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main FMT_MAIN = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		TESTS
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
#endif

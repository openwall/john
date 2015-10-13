/*
 * SHA-512 hashing, CUDA interface.
 * Please note that in current comparison function, we use computed a77
 * compares with ciphertext d80. For more details, refer to:
 * http://www.openwall.com/lists/john-dev/2012/04/11/13
 *
 * Copyright (c) 2012 myrice (interfacing to CUDA)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifdef HAVE_CUDA

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cuda_rawsha512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cuda_rawsha512);
#else

#include <string.h>

#include "stdint.h"
#include "arch.h"
#include "sha2.h"
#include "cuda_rawsha512.h"
#include "cuda_common.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "memdbg.h"

#define FORMAT_LABEL			"Raw-SHA512-cuda"
#define FORMAT_NAME			""
#define FORMAT_TAG			"" // FIXME: "$SHA512$" // format tag not supported here!
#define ALGORITHM_NAME			"SHA512 CUDA (inefficient, development use mostly)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define BINARY_ALIGN		sizeof(uint64_t)
#define SALT_ALIGN			1



static struct fmt_tests tests[] = {
	{"f342aae82952db35b8e02c30115e3deed3d80fdfdadacab336f0ba51ac54e297291fa1d6b201d69a2bd77e2535280f17a54fa1e527abc6e2eddba79ad3be11c0", "epixoip"},
	{FORMAT_TAG "f342aae82952db35b8e02c30115e3deed3d80fdfdadacab336f0ba51ac54e297291fa1d6b201d69a2bd77e2535280f17a54fa1e527abc6e2eddba79ad3be11c0", "epixoip"},
	{"b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", "password"},
	{"2c80f4c2b3db6b677d328775be4d38c8d8cd9a4464c3b6273644fb148f855e3db51bc33b54f3f6fa1f5f52060509f0e4d350bb0c7f51947728303999c6eff446", "john-user"},
	{"71ebcb1eccd7ea22bd8cebaec735a43f1f7164d003dacdeb06e0de4a6d9f64d123b00a45227db815081b1008d1a1bbad4c39bde770a2c23308ff1b09418dd7ed", "ALLCAPS"},
	{"82244918c2e45fbaa00c7c7d52eb61f309a37e2f33ea1fba78e61b4140efa95731eec849de02ee16aa31c82848b51fb7b7fbae62f50df6e150a8a85e70fa740c", "TestTESTt3st"},
	{"fa585d89c851dd338a70dcf535aa2a92fee7836dd6aff1226583e88e0996293f16bc009c652826e0fc5c706695a03cddce372f139eff4d13959da6f1f5d3eabe", "12345678"},
	{FORMAT_TAG "fa585d89c851dd338a70dcf535aa2a92fee7836dd6aff1226583e88e0996293f16bc009c652826e0fc5c706695a03cddce372f139eff4d13959da6f1f5d3eabe", "12345678"},
	{FORMAT_TAG "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", ""},
	{"c96f1c1260074832bd3068ddd29e733090285dfc65939555dbbcafb27834957d15d9c509481cc7df0e2a7e21429783ba573036b78f5284f9928b5fef02a791ef", "mot\xf6rhead"},
	{"aa3b7bdd98ec44af1f395bbd5f7f27a5cd9569d794d032747323bf4b1521fbe7725875a68b440abdf0559de5015baf873bb9c01cae63ecea93ad547a7397416e", "12345678901234567890"},
#if PLAINTEXT_LENGTH >=55
	{"db9981645857e59805132f7699e78bbcf39f69380a41aac8e6fa158a0593f2017ffe48764687aa855dae3023fcceefd51a1551d57730423df18503e80ba381ba", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
#if PLAINTEXT_LENGTH >= 111
	{"7aba4411846c61b08b0f2282a8a4600232ace4dd96593c755ba9c9a4e7b780b8bdc437b5c55574b3e8409c7b511032f98ef120e25467678f0458643578eb60ff", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"},
	// this one DOES NOT work for a 1 limb. Only 111 bytes max can be used, unless we do 2 sha512 limbs.
//	{"a5fa73a3c9ca13df56c2cb3ae6f2e57671239a6b461ef5021a65d08f40336bfb458ec52a3003e1004f1a40d0706c27a9f4268fa4e1479382e2053c2b5b47b9b2", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"},
#endif
#endif
#ifdef DEBUG //Special test cases.
	{"12b03226a6d8be9c6e8cd5e55dc6c7920caaa39df14aab92d5e3ea9340d1c8a4d3d0b8e4314f1f6ef131ba4bf1ceb9186ab87c801af0d5c95b1befb8cedae2b9", "1234567890"},
#if 0 // passwords too long for this implementation
	{"eba392e2f2094d7ffe55a23dffc29c412abd47057a0823c6c149c9c759423afde56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02", "123456789012345678901234567890"},
	{"3a8529d8f0c7b1ad2fa54c944952829b718d5beb4ff9ba8f4a849e02fe9a272daf59ae3bd06dde6f01df863d87c8ba4ab016ac576b59a19078c26d8dbe63f79e", "1234567890123456789012345678901234567890"},
	{"49c1faba580a55d6473f427174b62d8aa68f49958d70268eb8c7f258ba5bb089b7515891079451819aa4f8bf75b784dc156e7400ab0a04dfd2b75e46ef0a943e", "12345678901234567890123456789012345678901234567890"},
	{"8c5b51368ec88e1b1c4a67aa9de0aa0919447e142a9c245d75db07bbd4d00962b19112adb9f2b52c0a7b29fe2de661a872f095b6a1670098e5c7fde4a3503896", "123456789012345678901234567890123456789012345678901"},
	{"35ea7bc1d848db0f7ff49178392bf58acfae94bf74d77ae2d7e978df52aac250ff2560f9b98dc7726f0b8e05b25e5132074b470eb461c4ebb7b4d8bf9ef0d93f", "1234567890123456789012345678901234567890123456789012345"},
#endif
#endif
	{NULL}
};

extern void cuda_sha512(sha512_key *host_password, sha512_hash* host_hash,
                        int count);
extern void cuda_sha512_init();
extern int cuda_sha512_cmp_all(void *binary, int count);
extern void cuda_sha512_cpy_hash(sha512_hash* host_hash);

static sha512_key *gkey;
static sha512_hash *ghash;
uint8_t sha512_key_changed;
static uint8_t hash_copy_back;

static uint64_t H[8] = {
	0x6a09e667f3bcc908LL,
	0xbb67ae8584caa73bLL,
	0x3c6ef372fe94f82bLL,
	0xa54ff53a5f1d36f1LL,
	0x510e527fade682d1LL,
	0x9b05688c2b3e6c1fLL,
	0x1f83d9abfb41bd6bLL,
	0x5be0cd19137e2179LL
};

static void done(void)
{
	MEM_FREE(ghash);
	MEM_FREE(gkey);
}

static void init(struct fmt_main *self)
{
	gkey = mem_calloc(MAX_KEYS_PER_CRYPT, sizeof(sha512_key));
	ghash = mem_calloc(MAX_KEYS_PER_CRYPT, sizeof(sha512_hash));

	cuda_init();
	cuda_sha512_init();
}

static void copy_hash_back()
{
    if (!hash_copy_back) {
        cuda_sha512_cpy_hash(ghash);
        hash_copy_back = 1;
    }
}
static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos = ciphertext;
	/* Require lowercase hex digits (assume ASCII) */
	while (atoi16[ARCH_INDEX(*pos)] != 0x7F && (*pos <= '9' || *pos >= 'a'))
		pos++;
	return !*pos && pos - ciphertext == CIPHERTEXT_LENGTH;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char out[FULL_BINARY_SIZE];
	char *p = ciphertext;
	int i;
	uint64_t *b;
	for (i = 0; i < sizeof(out); i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	b = (uint64_t*)out;
	for (i = 0; i < 8; i++) {
		uint64_t t = SWAP64(b[i])-H[i];
		b[i] = SWAP64(t);
	}
	return out;
}

static int binary_hash_0(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_0;
}

static int binary_hash_1(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_1;
}

static int binary_hash_2(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_2;
}

static int binary_hash_3(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_3;
}

static int binary_hash_4(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_4;
}

static int binary_hash_5(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_5;
}

static int binary_hash_6(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_6;
}

static int get_hash_0(int index)
{
	copy_hash_back();
	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_0;
}

static int get_hash_1(int index)
{
	copy_hash_back();
	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_1;
}

static int get_hash_2(int index)
{
	copy_hash_back();
	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_2;
}

static int get_hash_3(int index)
{
	copy_hash_back();
	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_3;
}

static int get_hash_4(int index)
{
	copy_hash_back();
	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_4;
}

static int get_hash_5(int index)
{
	copy_hash_back();
	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_5;
}

static int get_hash_6(int index)
{
	copy_hash_back();
	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_6;
}

static void set_key(char *key, int index)
{
	int length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	gkey[index].length = length;
	memcpy(gkey[index].v, key, length);
	sha512_key_changed = 1;
}

static char *get_key(int index)
{
	gkey[index].v[gkey[index].length] = 0;
	return gkey[index].v;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

	cuda_sha512(gkey, ghash, count);
	sha512_key_changed = 0;
	hash_copy_back = 0;
	return count;
}

static int cmp_all(void *binary, int count)
{
	return cuda_sha512_cmp_all(binary, count);
}

static int cmp_one(void *binary, int index)
{
	uint64_t *t,*b = (uint64_t *) binary;
	copy_hash_back();
	t = (uint64_t *)ghash;
	if (b[3] != t[hash_addr(0, index)])
		return 0;
	return 1;
}

static int cmp_exact(char *source, int index)
{
	SHA512_CTX ctx;
	uint64_t crypt_out[8];
	int i;
	uint64_t *b,*c;

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, gkey[index].v, gkey[index].length);
	SHA512_Final((unsigned char *)(crypt_out), &ctx);

	b = (uint64_t *)get_binary(source);
	c = (uint64_t *)crypt_out;

	for (i = 0; i < 8; i++) {
		uint64_t t = SWAP64(c[i])-H[i];
		c[i] = SWAP64(t);
	}


	for (i = 0; i < FULL_BINARY_SIZE / 8; i++) { //examin 512bits
		if (b[i] != c[i])
			return 0;
	}
	return 1;

}

struct fmt_main fmt_cuda_rawsha512 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		FULL_BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		{ NULL },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		fmt_default_salt,
		{ NULL },
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
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

#endif /* plugin stanza */

#endif /* HAVE_CUDA */

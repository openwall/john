/*
 * JtR format to crack Enpass Password Manager databases.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru at openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if !__s390__

#if FMT_EXTERNS_H
extern struct fmt_main fmt_enpass;
#elif FMT_REGISTERS_H
john_register_one(&fmt_enpass);
#else

#include <string.h>
#include <stdint.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "aes.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "enpass_common.h"
#include "pbkdf2_hmac_sha512.h"

#define FORMAT_LABEL         "enpass"
#define FORMAT_NAME          "Enpass Password Manager"
#define FORMAT_TAG           "$enpass$"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME       "PBKDF2-SHA512 " SHA512_ALGORITHM_NAME
#else
#define ALGORITHM_NAME       "PBKDF2-SHA512 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     0x107
#define BINARY_SIZE          0
#define PLAINTEXT_LENGTH     125
#define SALT_SIZE            sizeof(struct custom_salt)
#define BINARY_ALIGN         1
#define SALT_ALIGN           sizeof(unsigned int)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT   SSE_GROUP_SZ_SHA512
#define MAX_KEYS_PER_CRYPT   4 * SSE_GROUP_SZ_SHA512
#else
#define MIN_KEYS_PER_CRYPT   1
#define MAX_KEYS_PER_CRYPT   4
#endif

#ifndef OMP_SCALE
#define OMP_SCALE            1 // MKPC and scale tuned for i7
#endif

#define FILE_HEADER_SZ       16
#define SQLITE_FILE_HEADER   "SQLite format 3"
#define SQLITE_MAX_PAGE_SIZE 65536

static struct fmt_tests enpass_tests[] = {				  {"$enpass$1$100000$73a0f3720c04e61c26a4062e4066a31143a8dd07540518981106cf7b9ec8c9b62d91803f0319c916056727309f4ac9adc9177a3c5e9c6873635e2512af9481443cc85362b67af2a14e32bdd063bd815276669ec17d4d23e1cd8859024eaeac1de36138fabfd001335be3b98b4404259c40a5797bca8763fd72a0cb5ba8ad06ab94677eaa9b4c7d2753b52c2caba82207a0e2b0213ecad22c4249ce6c708d0163d988d0cb2569b975b07ad7d7b773967f05a8a9392526e0b465f4e60c3a8021b346390f654384b58dda041b90bd1e6e3843ad62073e02bab8eba7d8ef9e1dac338890666fca758d46f4a45291b65e360c739c576742d6a12c2ebf2f70886a241424f75c33025aae6ff00245056a622d4f16df7df944a6bbdea8823c5d3640d82c3c939e1668962033863d51accfb6dd02b443b2078e68aa5e9e5b4fe226c2ab670713e214530a4c1c73989760cf8ba08a87c20f0a03e9fbc22c8be718d4af14b1a729d7494aa067bf9a9cb42e578bef9fea60e332c2a18e9de54188a083b997ae70b1f4a88f7d2f5e201c33e138b0b79e33c3c099873ec02acfa9da57712ea6115ee553bad7ca4ee775eeb1319c95a02c687060b0b47bd8d004e6b8f6b5a7095dd210c108d9800be471acac750ad33d332138e0fecac173dcc6b1b1aa4fd55d374f22db4f59fde21dfc2de77a2db12a8f1681180428483b2ac134078faf056ad511a515e0824d40dfd63f602d3dabe2be33c3bc5d8408519dbba5478195eb23095b79d7bb705bd0868899e0a12d06cc2d052f5c01c71937082662f6209697a5e6908aeafba6465897fae1b9fbbe42fadc52a823ce2aa191375ad2b93462c84fb74a9eb02b9391a34a3a8ad2c83d646bffa641e78245568fca9f35a07dad31baa7814de590ac63ed4182034bf4ff68be4b428ce1ea679ad146d378cf5de1049b5abe542684cb49183281d68596059691ded3e65913c84c63d49000a927bb6af9d3e2577ee992c9c5a0f952a84e3006a283fd02907421edd90bd5da21386b533a68b933914e0a7b7fa27535008310e0d40d1d6911573cd1d1900d085c509854c415c244aa3a9a937ca29d3f809ec12fc677c1fb70762c4e0e0c463702bdad82e2a6b6bcd2d83c7710a9013497c0a639e5f379e668eea4f4222f9f0f2d00a1ce438c8305d7b04cdb2380f50ee7d774149762d8f40061b743bf9dc7f8411f766e75e9b1c6fba94a1cae6171c27821fcf9b4b9bd3278066aa900f111cdd97cbffe9fad3aa7b5096457677cc544091727d6dfd738e9e2669288182620e3e0d161a0f2f58336f14def91d826be5623970860f0e847d894701e130ccbc822c1c550a4ad6a3be48e905f2fe8d1e837d246f767b0c8454827228c82103a612f405bf7f867ac69a28f880f843e26054012f33273b36870b9b6a82353457cdce1f49301051219", "openwall"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;
static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
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
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char master[MIN_KEYS_PER_CRYPT][32];
		unsigned char output[24];
		unsigned char *iv_in;
		unsigned char iv_out[16];
		int size, i;
		AES_KEY akey;

#ifdef SIMD_COEF_32
		int len[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			len[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			pout[i] = master[i];
		}
		pbkdf2_sha512_sse((const unsigned char **)pin, len, cur_salt->salt, 16, cur_salt->iterations, pout, 32, 0);
#else
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
			pbkdf2_sha512((unsigned char *)saved_key[index+i], strlen(saved_key[index+i]),
				cur_salt->salt, 16, cur_salt->iterations, master[i], 32, 0);
#endif
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			// memcpy(output, SQLITE_FILE_HEADER, FILE_HEADER_SZ);
			// See "sqlcipher_page_cipher" and "sqlite3Codec" functions
			size = page_sz - reserve_sz;
			iv_in = cur_salt->data + 16 + size;  // initial 16 bytes are salt
			memcpy(iv_out, iv_in, 16);
			AES_set_decrypt_key(master[i], 256, &akey);
			/*
			 * decrypting 8 bytes from offset 16 is enough since the
			 * verify_page function looks at output[16..23] only.
			 */
			AES_cbc_encrypt(cur_salt->data + 16, output + 16, 8, &akey, iv_out, AES_DECRYPT);
			if (enpass_common_verify_page(output) == 0)
				cracked[index+i] = 1;
			else
				cracked[index+i] = 0;
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void enpass_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_enpass = {
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
		{ NULL },
		{ FORMAT_TAG },
		enpass_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		enpass_common_valid,
		fmt_default_split,
		fmt_default_binary,
		enpass_common_get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		enpass_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#else /* __s390__ */

#if !defined(FMT_EXTERNS_H) && !defined(FMT_REGISTERS_H)
#warning ": Enpass: Format disabled on this arch"
#endif

#endif /* __s390__ */

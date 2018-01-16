/*
 * AxCrypt 1.x encrypted files cracker patch for JtR.
 * Written in 2016 by Fist0urs <eddy.maaalou at gmail.com>.
 *
 * This software is Copyright (c) 2016, Fist0urs <eddy.maaalou at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_axcrypt;
#elif FMT_REGISTERS_H
john_register_one(&fmt_axcrypt);
#else

#include <string.h>
#include <stdint.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "dyna_salt.h"
#include "sha.h"
#include "aes.h"
#include "memdbg.h"

#define FORMAT_LABEL            "axcrypt"
#define FORMAT_NAME             "AxCrypt"
#define FORMAT_TAG              "$axcrypt$*"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "SHA1 AES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define PLAINTEXT_LENGTH        125 /* actual max is 250 */
#define BINARY_SIZE             0
#define SALT_SIZE               sizeof(struct custom_salt *)
#define BINARY_ALIGN            MEM_ALIGN_NONE
#define SALT_ALIGN              sizeof(struct custom_salt *)
/* constant value recommended by FIPS */
#define AES_WRAPPING_IV         "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6"
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4

#ifndef OMP_SCALE
#define OMP_SCALE               2 // Tuned w/ MKPC for core i7
#endif

#define PUT_64BITS_XOR_MSB(cp, value) ( \
		(cp)[0] ^= (unsigned char)((value)), \
		(cp)[1] ^= (unsigned char)((value) >> 8), \
		(cp)[2] ^= (unsigned char)((value) >> 16), \
		(cp)[3] ^= (unsigned char)((value) >> 24 ) )

static struct fmt_tests axcrypt_tests[] = {
	/*
	 * Formats can be,
	 *   $axcrypt$*version*iterations*salt*wrappedkey
	 *   $axcrypt$*version*iterations*salt*wrappedkey*key-file
	*/
	{"$axcrypt$*1*1337*0fd9e7e2f907f480f8af162564f8f94b*af10c88878ba4e2c89b12586f93b7802453121ee702bc362", "Bab00nmoNCo|\\|2$inge"},
	{"$axcrypt$*1*60000*7522aa07694d441e47f8faad8a8cb984*95e02b7ccbdc27c227a80d1307505d8b769e87b32f312aa1", "nuNuche<3rewshauv"},
	{"$axcrypt$*1*31014*3408ae91dddc0b1750ed4223fd843364*1cc0f8fa8d89f44d284d0562ac7e93848c86ce9605907129", "tr0pO$phere5apointzero"},
	/* axcrypt created key-file */
	{"$axcrypt$*1*38574*ce4f58c1e85df1ea921df6d6c05439b4*3278c3c730f7887b1008e852e59997e2196710a5c6bc1813*66664a6b2074434a4520374d73592055626979204a6b755520736d6b4b20394e694a205548444320524578562065674b33202f42593d", "0v3rgo2|<fc!"},
	/* custom key-file */
	{"$axcrypt$*1*130885*8eb4d745f7ac3f7505bcf14e8ce7e3b4*5221a6e8277e90b0b4f16f7871fca02986fca55c0dec5e59*22486520646f65736e2774206c696b652047656f726765204d69636861656c3a20426f6f6f6f6f6f220d0a0d0a49206665656c20736f20756e737572650d0a417320492074616b6520796f75722068616e6420616e64206c65616420796f7520746f207468652062616e6365666c6f6f720d0a417320746865206d75736963207374617274732c20736f6d657468696e6720696e20796f757220657965730d0a43616c6c7320746f206d696e642074686520676f6c64656e2073637265656e0d0a416e6420616c6c206974277320736169642069732068690d0a0d0a49276d206e6576657220676f6e6e612064616e636520616761696e0d0a4775696c74792066656574206861766520676f74206e6f2072687974686d0d0a54686f7567682069742773206561737920746f2070726574656e640d0a49206b6e6f7720796f277265206e6f74206120666f6f6c0d0a0d0a53686f756c64277665206b6e6f776e20626574746572207468616e20746f206368656174206120667269656e640d0a416e6420776173746520746865206368616e636520746861742049277665206265656e20676976656e0d0a536f2049276d206e6576657220676f6e6e612064616e636520616761696e0d0a5468652077617920492064616e636564207769746820796f750d0a0d0a54696d652063616e206e65766572206d656e640d0a54686520636172656c657373207768697370657273206f66206120676f6f6420667269656e640d0a546f2074686520686561727420616e64206d696e640d0a49676e6f72616e6365206973206b696e640d0a54686572652773206e6f20636f6d666f727420696e207468652074727574680d0a5061696e20697320616c6c20796f75276c6c2066696e640d0a0d0a49276d206e6576657220676f6e6e612064616e636520616761696e0d0a4775696c74792066656574206861766520676f74206e6f2072687974686d0d0a54686f7567682069742773206561737920746f2070726574656e640d0a49206b6e6f7720796f75277265206e6f74206120666f6f6c0d0a0d0a492073686f756c64277665206b6e6f776e20626574746572207468616e20746f206368656174206120667269656e640d0a416e6420776173746520746865206368616e636520746861742049277665206265656e20676976656e0d0a536f2049276d206e6576657220676f6e6e612064616e636520616761696e0d0a5468652077617920492064616e636564207769746820796f750d0a0d0a4e6576657220776974686f757420796f7572206c6f76650d0a0d0a546f6e6967687420746865206d75736963207365656d7320736f206c6f75640d0a492077697368207468617420776520636f756c64206c6f736520746869732063726f77640d0a4d617962652069742773206265747465722074686973207761790d0a5765276420687572742065616368206f74686572207769746820746865207468696e677320776527642077616e7420746f207361790d0a0d0a576520636f756c642068617665206265656e20736f20676f6f6420746f6765746865720d0a576520636f756c642068617665206c6976656420746869732064616e636520666f72657665720d0a427574206e6f772077686f277320676f6e6e612064616e63652077697468206d650d0a506c6561736520737461790d0a0d0a416e642049276d206e6576657220676f6e6e612064616e636520616761696e0d0a4775696c74792066656574206861766520676f74206e6f2072687974686d0d0a54686f7567682069742773206561737920746f2070726574656e640d0a49206b6e6f7720796f75277265206e6f74206120666f6f6c0d0a0d0a53686f756c64277665206b6e6f776e20626574746572207468616e20746f206368656174206120667269656e640d0a416e6420776173746520746865206368616e636520746861742049277665206265656e20676976656e0d0a536f2049276d206e6576657220676f6e6e612064616e636520616761696e0d0a5468652077617920492064616e636564207769746820796f750d0a0d0a284e6f77207468617420796f7527726520676f6e6529204e6f77207468617420796f7527726520676f6e650d0a284e6f77207468617420796f7527726520676f6e65292057686174204920646964277320736f2077726f6e672c20736f2077726f6e670d0a5468617420796f752068616420746f206c65617665206d6520616c6f6e65", "careless whisper"},
	{NULL}
};

static char (*saved_key) [PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt {
	dyna_salt dsalt;
	int version;
	uint32_t key_wrapping_rounds;
	unsigned char salt[16];
	unsigned char wrappedkey[24];
	char* keyfile;
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
				sizeof(*saved_key));
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc(cracked_size, 1);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	char *ctcopy;
	char *keeptr;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;		/* skip over "$axcrypt$*" */
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* version */
		goto err;
	if (!isdec(p))
		goto err;
	if (!atoi(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if (!isdec(p))
		goto err;
	if (!atoi(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (strlen(p) != 32 || !ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* wrappedkey */
		goto err;
	if (strlen(p) != 48 || !ishexlc(p))
		goto err;
	/* optional key-file following */

	MEM_FREE(keeptr);
	return 1;
err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;
	static void *ptr;

	memset(&cs, 0, sizeof(cs));
	cs.keyfile = NULL;
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$axcrypt$*" */
	p = strtokm(ctcopy, "*");
	cs.version = atoi(p);

	p = strtokm(NULL, "*");
	cs.key_wrapping_rounds = (uint32_t) atoi(p);

	p = strtokm(NULL, "*");
	for (i = 0; i < 16; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	p = strtokm(NULL, "*");
	for (i = 0; i < 24; i++)
		cs.wrappedkey[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	/* if key-file present */
	if ((p = strtokm(NULL, "*")) != NULL){
		cs.keyfile = (char*) mem_calloc_tiny(strlen(p)/2 + 1, sizeof(char));
		for (i = 0; i < strlen(p)/2; i++)
			cs.keyfile[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	MEM_FREE(keeptr);

	cs.dsalt.salt_cmp_offset = SALT_CMP_OFF(struct custom_salt, salt);
	cs.dsalt.salt_cmp_size = SALT_CMP_SIZE(struct custom_salt, salt, wrappedkey, 0);
	cs.dsalt.salt_alloc_needs_free = 0;

	ptr = mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	memcpy(ptr, &cs, sizeof(struct custom_salt));

	return (void *) &ptr;
}

static void set_salt(void *salt)
{
	cur_salt = *(struct custom_salt **) salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		/*
		 * NUMBER_AES_BLOCKS = 2
		 * AES_BLOCK_SIZE = 16
		 */

		unsigned char KEK[20], lsb[24], cipher[16];
		AES_KEY akey;
		SHA_CTX ctx;

		int i, j, nb_iterations = cur_salt->key_wrapping_rounds;

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, (unsigned char *) saved_key[index],
					strlen(saved_key[index]));
		/* if key-file provided */
		if (cur_salt->keyfile != NULL)
			SHA1_Update(&ctx, (unsigned char *) cur_salt->keyfile,
						strlen(cur_salt->keyfile));
		SHA1_Final( KEK, &ctx );

		/* hash XOR salt => KEK */
		for (i = 0; i < sizeof(cur_salt->salt); i++)
			KEK[i] ^= cur_salt->salt[i];

		memcpy(lsb, cur_salt->wrappedkey + 8, 16);

		memset(&akey, 0, sizeof(AES_KEY));
		AES_set_decrypt_key(KEK, 128, &akey);

		/* set msb */
		memcpy(cipher, cur_salt->wrappedkey, 8);

		/* custom AES un-wrapping loop */
		for (j = nb_iterations - 1; j >= 0; j--) {

			/* 1st block treatment */
			/* MSB XOR (NUMBER_AES_BLOCKS * j + i) */
			PUT_64BITS_XOR_MSB(cipher, 2 * j + 2);
			/* R[i] */
			memcpy(cipher + 8, lsb + 8, 8);
			/* AES_ECB(KEK, (MSB XOR (NUMBER_AES_BLOCKS * j + i)) | R[i]) */
			AES_decrypt(cipher, cipher, &akey);
			memcpy(lsb + 8, cipher + 8, 8);

			/* 2nd block treatment */
			PUT_64BITS_XOR_MSB(cipher, 2 * j + 1);
			memcpy(cipher + 8, lsb, 8);
			AES_decrypt(cipher, cipher, &akey);
			memcpy(lsb, cipher + 8, 8);
		}
		if (!memcmp(cipher, AES_WRAPPING_IV, 8)) {
			cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return cracked[index];
}

static void axcrypt_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_axcrypt =
{
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{ NULL },
		{ FORMAT_TAG },
		axcrypt_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_dyna_salt_hash,
		NULL,
		set_salt,
		axcrypt_set_key,
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

#endif

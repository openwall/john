/*
 * Cracker for Oracle's O5LOGON protocol hashes. Hacked together during
 * September of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * O5LOGON is used since version 11g. CVE-2012-3137 applies to Oracle 11.1
 * and 11.2 databases. Oracle has "fixed" the problem in version 11.2.0.3.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Modifications (c) 2014 Harrison Neal, released under the same terms
 * as the original.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_o5logon;
#elif FMT_REGISTERS_H
john_register_one(&fmt_o5logon);
#else

#include <string.h>
#include <stdint.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "sha.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "aes.h"
#include "md5.h"

#define FORMAT_LABEL            "o5logon"
#define FORMAT_NAME             "Oracle O5LOGON protocol"
#define FORMAT_TAG              "$o5logon$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "SHA1 AES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        32 /* Multiple of 16 */
#define CIPHERTEXT_LENGTH       48
#define SALT_LENGTH             10
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(int32_t)
#define SALT_SIZE               sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      256

#ifndef OMP_SCALE
#define OMP_SCALE               8 // Tuned w/ MKPC on super
#endif

static struct fmt_tests o5logon_tests[] = {
	{"$o5logon$566499330E8896301A1D2711EFB59E756D41AF7A550488D82FE7C8A418E5BE08B4052C0DC404A805C1D7D43FE3350873*4F739806EBC1D7742BC6", "password"},
	{"$o5logon$3BB71A77E1DBB5FFCCC8FC8C4537F16584CB5113E4CCE3BAFF7B66D527E32D29DF5A69FA747C4E2C18C1837F750E5BA6*4F739806EBC1D7742BC6", "password"},
	{"$o5logon$ED91B97A04000F326F17430A65DACB30CD1EF788E6EC310742B811E32112C0C9CC39554C9C01A090CB95E95C94140C28*7FD52BC80AA5836695D4", "test1"},
	{"$o5logon$B7711CC7E805520CEAE8C1AC459F745639E6C9338F192F92204A9518B226ED39851C154CB384E4A58C444A6DF26146E4*3D14D54520BC9E6511F4", "openwall"},
	{"$o5logon$76F9BBAEEA9CF70F2A660A909F85F374F16F0A4B1BE1126A062AE9F0D3268821EF361BF08EBEF392F782F2D6D0192FD6*3D14D54520BC9E6511F4", "openwall"},
	{"$o5logon$C35A36EA7FF7293EF828B2BD5A2830CA28A57BF621EAE14B605D41A88FC2CF7EFE7C73495FB22F06D6D98317D63DDA71*406813CBAEED2FD4AD23", "MDDATA"},
	{"$o5logon$B9AC30E3CD7E1D7C95FA17E1C62D061289C36FD5A6C45C098FF7572AB9AD2B684FB7E131E03CE1543A5A99A30D68DD13*447BED5BE70F7067D646", "sys"},
	// the following hash (from HITCON 2014 CTF) revealed multiple bugs in this format (false positives)!
	// m3odbe
	// m3o3rt
	{"$o5logon$A10D52C1A432B61834F4B0D9592F55BD0DA2B440AEEE1858515A646683240D24A61F0C9366C63E93D629292B7891F44A*878C0B92D61A594F2680", "m3ow00"},
	{"$o5logon$52696131746C356643796B6D716F46474444787745543263764B725A6D756A69E46DE32AFBB33E385C6D9C7031F4F2B9*3131316D557239736A65", "123456"},
	{"$o5logon$4336396C304B684638634450576B30397867704F54766D71494F676F5A5A386F09F4A10B5908B3ED5B1D6878A6C78751*573167557661774E7271", ""},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int *cracked, any_cracked;

static struct custom_salt {
	unsigned char salt[SALT_LENGTH];         /* AUTH_VFR_DATA */
	unsigned char ct[CIPHERTEXT_LENGTH];     /* Server's AUTH_SESSKEY */
	unsigned char csk[CIPHERTEXT_LENGTH];    /* Client's AUTH_SESSKEY */
	unsigned char pw[16 + PLAINTEXT_LENGTH]; /* Client's AUTH_PASSWORD */
	int pw_len;                              /* AUTH_PASSWORD length (blocks) */
} *cur_salt;

static aes_fptr_cbc aesDec, aesEnc;

static void init(struct fmt_main *self)
{
	static char Buf[128];

	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	cracked = mem_calloc(self->params.max_keys_per_crypt,
	                     sizeof(*cracked));

	if (!*aesDec) {
		aesDec = get_AES_dec192_CBC();
		aesEnc = get_AES_enc192_CBC();
		sprintf(Buf, "%s %s", self->params.algorithm_name,
		        get_AES_type_string());
		self->params.algorithm_name=Buf;
	}
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int extra;

	if (strncmp(ciphertext,  FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	p = strtokm(ctcopy, "*"); /* server's sesskey */
	if (!p)
		goto err;
	if (hexlenu(p, &extra) != CIPHERTEXT_LENGTH * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (hexlenu(p, &extra) != SALT_LENGTH * 2 || extra)
		goto err;
	/* optional fields follow */
	if ((p = strtokm(NULL, "*"))) {	/* client's encrypted password */
		int len = hexlenu(p, &extra);

		if (extra || len < 64 || len % 32 || len > 2 * PLAINTEXT_LENGTH + 16)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* client's sesskey */
			goto err;
		if (hexlenu(p, &extra) != CIPHERTEXT_LENGTH * 2 || extra)
			goto err;
	}
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$o5logon$" */
	p = strtokm(ctcopy, "*");
	for (i = 0; i < CIPHERTEXT_LENGTH; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < SALT_LENGTH; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	/* Oracle 12 hashes may have more fields (optional for older ver) */
	if ((p = strtokm(NULL, "*"))) {
		cs.pw_len = hexlenu(p, 0) / 2 / 16 - 1;
		for (i = 0; p[i * 2]; i++)
			cs.pw[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		for (i = 0; i < CIPHERTEXT_LENGTH; i++)
			cs.csk[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}

	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	if (any_cracked) {
		memset(cracked, 0, sizeof(*cracked) * count);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char key[24];
		unsigned char iv[16];
		SHA_CTX ctx;

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, saved_key[index], saved_len[index]);
		SHA1_Update(&ctx, cur_salt->salt, 10);
		SHA1_Final(key, &ctx);
		memset(key + 20, 0, 4);

		if (cur_salt->pw_len) {
			int i;
			unsigned char s_secret[48];
			unsigned char c_secret[48];
			unsigned char combined_sk[24];
			unsigned char final_key[32];
			unsigned char password[16 + PLAINTEXT_LENGTH + 16];
			char *dec_pw = (char*)password + 16;
			int blen = (saved_len[index] + 15) / 16;
			MD5_CTX ctx;

			if (cur_salt->pw_len == blen) {
				memset(iv, 0, 16);
				aesDec(cur_salt->ct, s_secret, key, 3, iv);

				memset(iv, 0, 16);
				aesDec(cur_salt->csk, c_secret, key, 3, iv);

				for (i = 0; i < 24; i++)
					combined_sk[i] = s_secret[16 + i] ^ c_secret[16 + i];

				MD5_Init(&ctx);
				MD5_Update(&ctx, combined_sk, 16);
				MD5_Final(final_key, &ctx);
				MD5_Init(&ctx);
				MD5_Update(&ctx, combined_sk + 16, 8);
				MD5_Final(final_key + 16, &ctx);

				memset(iv, 0, 16);
				aesDec(cur_salt->pw, password, final_key,
				       cur_salt->pw_len + 1, iv);

				if (!memcmp(dec_pw, saved_key[index], saved_len[index]))
				{
					char *p = dec_pw + 16 * blen - 1;
					int n, pad;
					int res = 1;

					n = pad = *p;
					while (n--) {
						if (*p-- != pad) {
							res = 0;
							break;
						}
					}

					if (res) {
						cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
						any_cracked |= 1;
					}
				}
			}
		} else {
			unsigned char pt[16];

			memcpy(iv, cur_salt->ct + 16, 16);
			aesDec(cur_salt->ct + 32, pt, key, 1, iv);

			if (!memcmp(pt + 8, "\x08\x08\x08\x08\x08\x08\x08\x08", 8))
			{
				cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
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
	return 1;
}

static void o5logon_set_key(char *key, int index)
{
	saved_len[index] =
		strnzcpyn(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_o5logon = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD,
		{ NULL },
		{ FORMAT_TAG },
		o5logon_tests
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
		fmt_default_salt_hash,
		NULL,
		set_salt,
		o5logon_set_key,
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

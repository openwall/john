/*
 * JtR format to crack password of BestCrypt v4 encrypted volume
 *
 * This implementation relies on findings from @trounce1 and @kholia
 * reverse-engineering work
 * Copyright (c) 2021 Jean-Christophe Delaunay <jean-christophe.delaunay [at] synacktiv.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_bestcrypt_ve;
#elif FMT_REGISTERS_H
john_register_one(&fmt_bestcrypt_ve);
#else

#include <string.h>
#include <errno.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "yescrypt/yescrypt.h"
#include "aes.h"
#include "twofish.h"
#include "serpent.h"
#include <openssl/camellia.h>
#include "sha.h"

#define FORMAT_NAME             "BestCrypt Volume Encryption v4"
#define FORMAT_LABEL            "BestCryptVE4"
#define FORMAT_TAG              "$bcve$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)

#if !defined(JOHN_NO_SIMD) && defined(__XOP__)
#define SCRYPT_ALGORITHM_NAME "Salsa20/8 128/128 XOP"
#elif !defined(JOHN_NO_SIMD) && defined(__AVX__)
#define SCRYPT_ALGORITHM_NAME "Salsa20/8 128/128 AVX"
#elif !defined(JOHN_NO_SIMD) && defined(__SSE2__)
#define SCRYPT_ALGORITHM_NAME "Salsa20/8 128/128 SSE2"
#else
#define SCRYPT_ALGORITHM_NAME "Salsa20/8 32/" ARCH_BITS_STR
#endif
#define ALGORITHM_NAME          "scrypt " SCRYPT_ALGORITHM_NAME ", AES/TwoFish/Serpent/Camellia"

#define BENCHMARK_COMMENT       " (32768, 16, 1)"
#define BENCHMARK_LENGTH        0x507
#define BINARY_SIZE             0
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(*cur_salt)
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(int)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define OMP_SCALE               1

#define aesId                   8
#define twofishId               9
#define serpentId               10
#define rc6Id                   11
#define camelliaId              15

#define SERPENT_KS (140 * 4)

static struct fmt_tests tests[] = {
	{"$bcve$4$8$4944e8bfed6c688b6b30ed3aedb21c9efeba82a1425ebf8e$a4b51d5e6d0b15ba039d0a62cb1a2f4a1d0f6c0325658b15334657b7732a6dc4ec72de7a7c04216d0dd5167bc23e384ac99bca490307445bcbeeaf09da15465ba6540daa52422afdce6f199f92632e0675d9f90693a49ec964beb2358c7a95ff", "openwall"},
	{"$bcve$4$8$4afeb70b633687b1869fb6f99c988930688391478d730672$e1c4c86980e60aaebb55b2857be43055aae966925812687481e6844a3ded5480f51302cdd633e040a30790abdd8ea520e28ec7a261e4226bdc3019b1905fe1df1fbbbc98b7ee409ef2ba8be359cf18ccc2f9f9dbeb20d75c5445c35d77e03907","B4by$harKtudududu!"},
	{"$bcve$4$9$06046a1b1bde8dca9df92696f600ce54b0084cdde00e6e07$f708a6916dbe91d105e689089ca70c37dc18e761773154f28063932ead9eebdcf9fb478ce48923408eb15ccfec99e44372d47bff9aca6b96ba10d9f8c0b9d6b57b75f27f359bef6e632370fd701fca2160f46d39fffcefb30e769bafb87cbd32", "openwall123!"},
	{"$bcve$4$10$65c70a51ec78c46a17e0604804f8ef297b118a42c8109b05$2f92091413f51a446b8576d06790d682b251a97694d19786c45a9245dacb5100fcfc757ba993a83e6f8e13da0d726c57bdf28e70beaa734034c69cd7f655afaebf6c3cf1a0617f673e267b6e5bc7a3619c9eb6801aa8f1a1824ed3cca55ece0d", "!1234openwall"},
	//{"$bcve$4$11$5fbbb914874770659e46e7f5a72b506076271bfebcaed823$7216a0b623354b0f2ed417a121cbbed39e0a1ce84c86cd4c5dbe75cbe00b0e947f1cda7e10d7ce7c88f479c086aa672d4c4610896cbf81f6dff82e16d0648d3adbadc271058c7f0edb40a599bca7fbc8eefb26be106b182595e4fa68fcf47b9c", "!1234openwall"},
	{"$bcve$4$15$1386f84fa770e372d9221bb4e4aaf8ee2e0d40e19b69917c$f7a0c8bcdf279fe29f5ab144da729e9dc0c4ca12efb1e2be25e417f30db78227831bb8ee1bee84b0cd37582af2aaa34102fcc851729d676630d7f3de34f6258bd639e6a96301df4038601b30961d35b502506bf4b4d373e9f007b95f9b1abeb2", "openwall123!"},
	{NULL}
};

static int max_threads;
static yescrypt_local_t *local;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int *cracked;
static int any_cracked;
static size_t cracked_size;

static struct custom_salt {
	int version;
	int enc_algoID;
	unsigned char salt[24];
	unsigned char encrypted_data[0x60];
} *cur_salt;

/* ripped from ossl_aes_crypto.c */
static void serpent_cbc_decrypt(const unsigned char *in, unsigned char *out,
                                size_t len, void *key,
                                unsigned char ivec[16])
{
	uint32_t n;
	union { uint32_t t[16/sizeof(uint32_t)]; unsigned char c[16]; } tmp;

//	assert(in && out && key && ivec);
	while (len) {
		unsigned char c;
		serpent_decrypt(in, tmp.c, key);
		for (n=0; n<16 && n<len; ++n) {
			c = in[n];
			out[n] = tmp.c[n] ^ ivec[n];
			ivec[n] = c;
		}
		if (len<=16) {
			for (; n<16; ++n)
				ivec[n] = in[n];
			break;
		}
		len -= 16;
		in  += 16;
		out += 16;
	}
}

int Twofish_Decrypt_no_padding(Twofish_key *m_key, Twofish_Byte *pInput, Twofish_Byte *pOutBuffer,
                               int nInputOctets, Twofish_Byte *m_pInitVector)
{
	int i, numBlocks;
	Twofish_UInt32 iv[4];
	union {
		Twofish_Byte block[16];
		Twofish_UInt32 p32[4];	// needed for 'requires aligned' machines
	} x;
	Twofish_UInt32 *p;
	Twofish_Byte *block;

	p = x.p32;
	block = x.block;
	if ((pInput == NULL) || (nInputOctets <= 0) || (pOutBuffer == NULL)) return 0;

	if ((nInputOctets % 16) != 0) { return -1; }

	numBlocks = nInputOctets / 16;

	memcpy(iv, m_pInitVector, 16);

	for (i = numBlocks; i > 0; i--)
	{
		Twofish_decrypt(m_key, (Twofish_Byte *)pInput, (Twofish_Byte *)block);
		p[0] ^= iv[0];
		p[1] ^= iv[1];
		p[2] ^= iv[2];
		p[3] ^= iv[3];
		memcpy(iv, pInput, 16);
		memcpy(pOutBuffer, block, 16);
		pInput += 16;
		pOutBuffer += 16;
	}

	return 16*numBlocks;
}

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

#ifdef _OPENMP
	max_threads = omp_get_max_threads();
#else
	max_threads = 1;
#endif

	local = mem_alloc(sizeof(*local) * max_threads);
	int i;
	for (i = 0; i < max_threads; i++)
		yescrypt_init_local(&local[i]);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_len));
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	//cracked_count = self->params.max_keys_per_crypt;
	any_cracked = 0;

	Twofish_initialise();
}

static void done(void)
{
	int i;
	for (i = 0; i < max_threads; i++)
		yescrypt_free_local(&local[i]);
	MEM_FREE(local);

	MEM_FREE(saved_key);
	MEM_FREE(cracked);
	MEM_FREE(saved_len);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext, *ctcopy, *keeptr;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // version
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) // encryption algorithm
		goto err;
	if (!isdec(p))
		goto err;
	if (atoi(p) != 8 && atoi(p) != 9 && atoi(p) != 10 && atoi(p) != 11 && atoi(p) != 15)
		goto err;
	if (atoi(p) == 11) {
		fprintf(stderr, "Warning: " FORMAT_LABEL ": RC6 encryption not supported yet!\n");
		goto err;
	}
	if ((p = strtokm(NULL, "$")) == NULL) // salt
		goto err;
	if (hexlenl(p, &extra) != sizeof(cur_salt->salt) * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) // encrypted content
		goto err;
	if (hexlenl(p, &extra) != sizeof(cur_salt->encrypted_data) * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i;
	char *p = ciphertext, *ctcopy, *keeptr;
	memset(&cs, 0, sizeof(cs));

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	cs.version = atoi(p);
	p = strtokm(NULL, "$");
	cs.enc_algoID = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < sizeof(cs.salt); i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];
	p = strtokm(NULL, "$");
	for (i = 0; i < sizeof(cs.encrypted_data); i++)
		cs.encrypted_data[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];

	MEM_FREE(keeptr);

	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void bcve_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
	int failed = 0;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

	static const yescrypt_params_t params = { .N = 0x8000, .r = 16, .p = 1 };

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char kdf_out[32];
		/* BestCrypt uses CBC mode with a null IV */
		unsigned char iv[16] = {0};
		unsigned char out[sizeof(cur_salt->encrypted_data)];

		SHA256_CTX ctx;
		unsigned char sha256_hash[32];

#ifdef _OPENMP
		int t = omp_get_thread_num();
		if (t >= max_threads) {
			failed = -1;
			continue;
		}
#else
		const int t = 0;
#endif
		if (yescrypt_kdf(NULL, &local[t],
		             (const uint8_t *)saved_key[index],
		             strlen(saved_key[index]),
		             (const uint8_t *)cur_salt->salt,
		             sizeof(cur_salt->salt),
		             &params,
		             kdf_out, sizeof(kdf_out))){
			failed = errno ? errno : EINVAL;
#ifndef _OPENMP
			break;
#endif
		}
		/*
		   we will now use output of scrypt as key for desired encryption
		   algorithm in CBC mode
		*/
		if (cur_salt->enc_algoID == aesId) {
			AES_KEY aes_key;

			AES_set_decrypt_key(kdf_out, 256, &aes_key);
			AES_cbc_encrypt(cur_salt->encrypted_data,
			                out,
			                sizeof(cur_salt->encrypted_data),
			                &aes_key,
			                iv,
			                AES_DECRYPT);
		} else if(cur_salt->enc_algoID == twofishId) {
			Twofish_key tkey;

			Twofish_prepare_key(kdf_out, sizeof(kdf_out), &tkey);
			Twofish_Decrypt_no_padding(&tkey,
			                           cur_salt->encrypted_data,
			                           out,
			                           sizeof(cur_salt->encrypted_data),
			                           iv);
		} else if(cur_salt->enc_algoID == serpentId) {
			uint8_t ks[SERPENT_KS];

			serpent_set_key(kdf_out, ks);
			serpent_cbc_decrypt(cur_salt->encrypted_data,
			                    out,
			                    sizeof(cur_salt->encrypted_data),
			                    ks,
			                    iv);
		} else if(cur_salt->enc_algoID == camelliaId) {
			CAMELLIA_KEY ck;

			Camellia_set_key(kdf_out, 256, &ck);
			Camellia_cbc_encrypt(cur_salt->encrypted_data,
			                     out,
			                     sizeof(cur_salt->encrypted_data),
			                     &ck,
			                     iv,
			                     CAMELLIA_DECRYPT);
		} /* else if(cur_salt->enc_algoID == rc6Id) {
			TODO
		}
		*/

		/* we now compute sha256(decrypted_content[0:0x40]) and
		compare it with decrypted_content[0x40:0x60] */
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, out, 0x40);
		SHA256_Final(sha256_hash, &ctx);
		cracked[index] = (0 == memcmp(sha256_hash, out + 0x40, 0x20));
#ifdef _OPENMP
#pragma omp atomic
#endif
		any_cracked |= 1;
	}

	if (failed) {
#ifdef _OPENMP
		if (failed < 0) {
			fprintf(stderr, "OpenMP thread number out of range\n");
			error();
		}
#endif
		fprintf(stderr, "scrypt failed: %s\n", strerror(failed));
		error();
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

struct fmt_main fmt_bestcrypt_ve = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{
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
		fmt_default_binary,
		get_salt,
		{},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		bcve_set_key,
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

#endif /* HAVE_LIBCRYPTO */

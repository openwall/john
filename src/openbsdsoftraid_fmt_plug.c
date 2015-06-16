/*
 * Copyright (c) 2014 Thiébaud Weksteen <thiebaud at weksteen dot fr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Fixed BE issues, and build problems (Fall 2014), JimF.
 */

#include "arch.h"

#if FMT_EXTERNS_H
extern struct fmt_main fmt_openbsd_softraid;
#elif FMT_REGISTERS_H
john_register_one(&fmt_openbsd_softraid);
#else

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "common.h"
#include "formats.h"
#include "pbkdf2_hmac_sha1.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE                   1
#endif
#endif
#include "memdbg.h"

#define PLAINTEXT_LENGTH            125
#define SALT_SIZE                   sizeof(struct custom_salt)
#define SALT_ALIGN                  4
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT          SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT          SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT          1
#define MAX_KEYS_PER_CRYPT          1
#endif

#define OPENBSD_SOFTRAID_SALTLENGTH 128
#define OPENBSD_SOFTRAID_KEYS       32
#define OPENBSD_SOFTRAID_KEYLENGTH  64  /* AES-XTS-256 keys are 512 bits long */
#define OPENBSD_SOFTRAID_MACLENGTH  20
#define BINARY_SIZE                 OPENBSD_SOFTRAID_MACLENGTH
#define BINARY_ALIGN                sizeof(ARCH_WORD_32)

static char (*key_buffer)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	unsigned int  num_iterations;
	unsigned char salt[OPENBSD_SOFTRAID_SALTLENGTH];
	unsigned char masked_keys[OPENBSD_SOFTRAID_KEYLENGTH * OPENBSD_SOFTRAID_KEYS];
} *cur_salt;

static void init(struct fmt_main *self)
{
	OpenSSL_add_all_algorithms();
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	key_buffer = mem_calloc_tiny(sizeof(*key_buffer) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char* ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	int i;
	char *p;

	if (strncmp(ciphertext, "$openbsd-softraid$", 18) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 18;

	if ((p = strtokm(ctcopy, "$")) == NULL)
		goto err;
	i = atoi(p);
	if (i < 0)                /* iterations */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)
		goto err;
	if (strlen(p) != 2 * 128) /* salt */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)
		goto err;
	if (strlen(p) != 2 * 32 * 64) /* masked keys */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)
		goto err;
	if (strlen(p) != 2 * BINARY_SIZE) /* HMAC-SHA1 */
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void* get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;

	ctcopy += 18;
	p = strtokm(ctcopy, "$"); /* iterations */
	cs.num_iterations = atoi(p);
	p = strtokm(NULL, "$");   /* salt */
	for (i = 0; i < OPENBSD_SOFTRAID_SALTLENGTH ; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");   /* masked keys */
	for (i = 0; i < OPENBSD_SOFTRAID_KEYLENGTH * OPENBSD_SOFTRAID_KEYS; i++)
		cs.masked_keys[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);
	return (void *)&cs;
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
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
		AES_KEY akey;
		unsigned char mask_key[MAX_KEYS_PER_CRYPT][32];
		unsigned char unmasked_keys[OPENBSD_SOFTRAID_KEYLENGTH * OPENBSD_SOFTRAID_KEYS];
		unsigned char hashed_mask_key[20];
		int i, j;

		/* derive masking key from password */
#ifdef SSE_GROUP_SZ_SHA1
    int lens[SSE_GROUP_SZ_SHA1];
    unsigned char *pin[SSE_GROUP_SZ_SHA1], *pout[SSE_GROUP_SZ_SHA1];
    for (i = 0; i < SSE_GROUP_SZ_SHA1; ++i) {
      lens[i] = strlen(key_buffer[index+i]);
      pin[i] = (unsigned char*)key_buffer[index+i];
      pout[i] = mask_key[i];
    }
    pbkdf2_sha1_sse((const unsigned char **)pin, lens,
        cur_salt->salt, OPENBSD_SOFTRAID_SALTLENGTH,
        cur_salt->num_iterations, (unsigned char**)pout,
        32, 0);
#else
    pbkdf2_sha1((const unsigned char*)(key_buffer[index]),
        strlen(key_buffer[index]),
        cur_salt->salt, OPENBSD_SOFTRAID_SALTLENGTH,
        cur_salt->num_iterations, mask_key[0],
        32, 0);
#endif

    for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {

#if !ARCH_LITTLE_ENDIAN
      alter_endianity(mask_key[i], 32);
#endif

      /* decrypt sector keys */
      AES_set_decrypt_key(mask_key[i], 256, &akey);
      for(j = 0; j < (OPENBSD_SOFTRAID_KEYLENGTH * OPENBSD_SOFTRAID_KEYS) / 16;  j++) {
        AES_decrypt(&cur_salt->masked_keys[16*j], &unmasked_keys[16*j], &akey);
      }

      /* get SHA1 of mask_key */
      SHA1(mask_key[i], 32, hashed_mask_key);

      /* get HMAC-SHA1 of unmasked_keys using hashed_mask_key */
      HMAC(EVP_sha1(), hashed_mask_key, OPENBSD_SOFTRAID_MACLENGTH,
          unmasked_keys, OPENBSD_SOFTRAID_KEYLENGTH * OPENBSD_SOFTRAID_KEYS,
          (unsigned char*)crypt_out[index+i], NULL);
    }

	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (*(ARCH_WORD_32*)binary == *(ARCH_WORD_32*)(crypt_out[index]))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return (*(ARCH_WORD_32*)binary == *(ARCH_WORD_32*)(crypt_out[index]));
}

static int cmp_exact(char *source, int index)
{
	void *bin = get_binary(source);
	return !memcmp(bin, crypt_out[index], 20);
}

static void jtr_set_key(char* key, int index)
{
	strcpy(key_buffer[index], key);
}

static char *get_key(int index)
{
	return key_buffer[index];
}
#if FMT_MAIN_VERSION > 11
/* report iteration count as tunable cost */
static unsigned int iteration_count(void *salt)
{
	return ((struct custom_salt*)salt)->num_iterations;
}
#endif
static struct fmt_tests tests_openbsdsoftraid[] = {
	// too long of line was causing my Sparc box to fail to compile this code
	{"\
$openbsd-softraid$8192$c2891132ca5305d1189a7da94d32de29182abc2f56dc641d685e471935f2646e06b79f1d6c102c2f62f3757a20efb0a110b8ae207f9129f0dc5eea8ab05cc8280e0ba2460faf979dbac9f577c4a083349064364556b7ad15468c17c4d794c3da0ddf5990cc66751a6ded8d534531dd9aa9fce2f43e68d6a7200e135beb55e752$311c42d1d8daf1e47e0150c8d4a455a0567b062970c1838faaedcd3e43795545de64971c7598902a6e2c3fffcf8abe2ef78979164d0c9089fbb931c4c9dac8b86c85eeace11095e38487e41eb7b6094d96c339e86686121fbe1c32dbff3c00706926b22ec3a1329f346c599d132105b5d182a380161504d535f9836bb7286331adce1e47e4e251a0249612a94312bb309a6f4558568467731c1ae8c9b910d27102dca2a72228ffde7bfc60004c8ab33ca2b01aa476c4f42f99a3d1f904e3bbc56270edb314a62e92cf68185ace93731ef4ce08dff3c695c45e35b57ed8ab1552114635eb2ff531437ba5c3a08ebf3e73b6bbb7fe1ad98373da349f09284ae819b6a2f6fc5a10aec347f3c2331abc1d6617e77d68f314fdb683294f3ef351869491c4fb096969924215d711c15e5fce533dc5acaed4a473b14c595bababc178e62ef065770716520ecddc7cbf1cbed1250b7e004ab975bc29780c952087ec382bf6e77447720a10a8c2993262a2b21f8a3f47e35daa5b620573626b474d3e8abf8e73164664b041a18fe35c2a1905fad617bf6e6c380fdeeb680fa89b6c6dc7676ad93fde25076ecb8855d623b45af9a16a62a957d85c4c70896019be1827ad9320a69f18bdfc2674f04babdbfcd679c0ef22f7ab2a18818b9b425e61d8c06196a23babd0aefd5a00f1b297a66d973daae40f4dbd9be60d8953fafbd51f7745e2d04b5c80b63ad1f550cd939490b346d4fe7c1fc266d593bcafac0d8989994e174de6d1ef4ce78b3224ea4e68ccbf998654a067558537be332f5cae4b44c18664428d45b71cde5b53bedddf8a7daf47fce212578b72\
7e420c91de0baa1108683dd5b5534e81f4fe945d27fd9d28934afc8d15d95932952c0be717d4d87bb8255bf658a083c3aed643f7a6cfb56fbcbdab9e0a7348b0a3a91e3d560d1ec96f5769551e64beb54a499f6d6dd37e4361d484fe4f7bac4dc26c8a1a2609592d527b134c8212d71b3578217e0ec1da317c69e7e8c39d2d5b2d4073fa9c618a01a092b61613f6f1e41e6ab43d8ca010f177947aeab2884e9a4dd28453ff5bdadb765680733e7af1463ec1b20b879ae01c9256da0207811f956b3950f6db743a9e34a6d8f0fdfa5c47b4f807f0017c2092d72dc19d111711e796ffc4035da3a4caa6a5301491d0473b0d47cd01b705ff11a10263867013a11c65462c311fa5ac9a2598142779b55f09dbec89ac18049c29e5baf3aa38696a3b92d08b02cb10af5389e06058b3ad8be09b121e4e320520413775b7c6fbb3f2b332e3ac0295a4a4dfb4a56ea1c32bc28c149ffaa3b426f5a17a11afe56426b38966c86734654fe05a611c8f025ee4092656c097bbf59743c31508fa9e80ff86a2ae33d401ec316e65eef251d173e9565ffc1672b8b341174427a851a6a4c42554848c637283d13d4ba5b5414b4e61ade6ec7ef7b77186a81adff381e6a79d3dac2c68bf386f100fef1c354221a2ba3d8a7a10460f637eaa152ab79027ab94e5965660de3ed66dac4a0f8e75b85d768e51c8e82a26cb81249ca8d249d8c5cdc8bd55289679d3915a397d31863334df18e2fe3ef9069b064c4ef6b418e5388817040ae9922e5e9f57a8bf3b3fe04748b9cf5068ac86f942b4068853602a6c6c794423569b665b359d5f947c2e5ff194d23d953b435b2b3834513fdfda2b66fcea22883690b1cc56c2fcaa5600895ff8d8ae9e3a6a2b6258ff873242d1128b20e7d1e843ade1bd206b541eba02a214a95cd83860865f947cb4adbd465957055060df05e53fa9ea4b29867c92b224be939d3715be0e61b7aa0e24a8f25bccfa3b7901a3f0a8cb25498d7c9899d435b409220723dcde1d38ab6d4e7cfb42d443c9b65a37\
53891f46adb9bc52574699a7b642955702ed662d04cbe21aeec7c15db7e325dcaa74c85c5e3ed54424642d5bd8d3109c2d4c0079b3d2c5f2da12ad5b25407ae48f6fe4fc653b23a7f2d56a93c898dd0bd59ba02295934c9f7ffb433ef611d51b7c203f374cf9e8b69d4952ccc44593447ad41540270b0e30c349401048cbce10a0e1bae373de15c878982b0af837fb5432cd2471516d1e218296ce462a59fd5412921bbd3f75cf65070f7bafe21105ba83f7ffe8ece71534863c0dd731a2f3c29fff97b8ce798890a1b158a8891bb6f2dd751e75c0cb0db7ea152d7cdc91663f46f85d12ce0015351dba5225b2a87b64cc30518b23e31b2bfbb0b2a5042eeaea1234a57549a3e55ddd708e3380df032e93071b10b3e6902152c90ffd99bda0177a197779341307c5d9f335e698259ade70564eab9d2856aa1aa814211e71ba2885ef9cd5f5bdd225af2f6eebf775cc0bbdb3e519edb7c49a9a1984cc0cc012679aca8fd1d002fa64b2df095b4a9e2b496e3f4b544955c817efb29562cf8b3d2eeccbe4d364ce71d2d12b504b11de4747139ef505bdd12f382eb02fa3f5272b710644a9c20660ca5b4fa74be60984240b555c1f34261ee1d72d9eb2cc680f32b4603865503addc3a1fdc49d2b158d3407a282edd72ef51ad021338fdebf413726e1778e3bc3909b670d3f40e824391c5525b162ea01c29205e12f8e62bdd8cd0f21f6f7b44af4521c2dd23a7f3508e5dc6fffa3365e4ca1cac33bb515a5c5495dc059a94396de7d802758b65bb4cecb90bf69ab4126eab85958cb8b64eedf3a0955ab42cdc98ef90620e10cc854b9c02bfaff60742494a0c3bb34ef6d6bb861b275d975bdc4a10ac922dc70c1b03a4c01943a704af36ec8d79cf2f9ce0f602f01bef4a32edeb8fbba863c945552efc814410ac6bb839349ea65879644003bdda35d40eabdc9dcfb2d67d945b7f111ab62591763a0dd2d338594eff004237e5acce69dd9d2cdbb9ce121bd$5337e4ba9d877a1e84559688386fbc844c5fe557", "password1" },
	{NULL}
};

#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1 32/" ARCH_BITS_STR
#endif

struct fmt_main fmt_openbsd_softraid = {
	{
		"OpenBSD-SoftRAID",               // FORMAT_LABEL
		"",                               // FORMAT_NAME
		ALGORITHM_NAME,
		" (8192 iterations)",             // BENCHMARK_COMMENT
		-1,                               // BENCHMARK_LENGTH
		0,
		PLAINTEXT_LENGTH,
		sizeof(ARCH_WORD_32), //BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		tests_openbsdsoftraid
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		jtr_set_key,
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

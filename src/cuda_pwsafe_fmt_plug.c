/* Password Safe cracker patch for JtR. Hacked together during May of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * CUDA port by Lukas Odzioba <ukasz at openwall dot net>
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#ifdef HAVE_CUDA

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cuda_pwsafe;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cuda_pwsafe);
#else

#include <string.h>
#include <assert.h>
#include <errno.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "memory.h"
#include "cuda_pwsafe.h"
#include "cuda_common.h"
#include "memdbg.h"

#define FORMAT_LABEL            "pwsafe-cuda"
#define FORMAT_NAME             "Password Safe"
#define ALGORITHM_NAME          "SHA256 CUDA"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define PLAINTEXT_LENGTH        23 /* Max. for one limb: 23+32=55 */
#define BINARY_SIZE             0
#define SALT_SIZE               sizeof(pwsafe_salt)
#define MIN_KEYS_PER_CRYPT      THREADS
#define MAX_KEYS_PER_CRYPT      KEYS_PER_CRYPT

#define BINARY_ALIGN		1
#define SALT_ALIGN			sizeof(uint32_t)

static struct fmt_tests pwsafe_tests[] = {
        {"$pwsafe$*3*fefc1172093344c9d5577b25f5b4b6e5d2942c94f9fc24c21733e28ae6527521*2048*88cbaf7d8668c1a98263f5dce7cb39c3304c49a3e0d76a7ea475dc02ab2f97a7", "12345678"},
        {"$pwsafe$*3*581cd1135b9b993ccb0f6b01c1fcfacd799c69960496c96286f94fe1400c1b25*2048*4ab3c2d3af251e94eb2f753fdf30fb9da074bec6bac0fa9d9d152b95fc5795c6", "openwall"},
	{"$pwsafe$*3*34ba0066d0fc594c126b60b9db98b6024e1cf585901b81b5b005ce386f173d4c*2048*cc86f1a5d930ff19b3602770a86586b5d9dea7bb657012aca875aa2a7dc71dc0", "12345678901234567890123"},
#if PLAINTEXT_LENGTH >= 27
	{"$pwsafe$*3*a42431191707895fb8d1121a3a6e255e33892d8eecb50fc616adab6185b5affb*2048*0f71d12df2b7c5394ae90771f6475a7ad0437007a8eeb5d9b58e35d8fd57c827", "123456789012345678901234567"},
#endif
#if PLAINTEXT_LENGTH >= 87
        {"$pwsafe$*3*c380dee0dbb536f5454f78603b020be76b33e294e9c2a0e047f43b9c61669fc8*2048*e88ed54a85e419d555be219d200563ae3ba864e24442826f412867fc0403917d", "this is an 87 character password to test the max bound of pwsafe-opencl................"},
#endif
        {NULL}
};


static pwsafe_pass *host_pass;                          /** binary ciphertexts **/
static pwsafe_salt *host_salt;                          /** salt **/
static pwsafe_hash *host_hash;                          /** calculated hashes **/
extern void gpu_pwpass(pwsafe_pass *, pwsafe_salt *, pwsafe_hash *, int count);

static void done(void)
{
	MEM_FREE(host_salt);
	MEM_FREE(host_hash);
	MEM_FREE(host_pass);
}

static void init(struct fmt_main *self)
{
	host_pass = mem_calloc(KEYS_PER_CRYPT, sizeof(pwsafe_pass));
	host_hash = mem_calloc(KEYS_PER_CRYPT, sizeof(pwsafe_hash));
	host_salt = mem_calloc(1, sizeof(pwsafe_salt));
	cuda_init();
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	// format $pwsafe$version*salt*iterations*hash
	char *p;
	char *ctcopy;
	char *keeptr;
	if (strncmp(ciphertext, "$pwsafe$*", 9) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 9;		/* skip over "$pwsafe$*" */
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* version */
		goto err;
	if (!isdec(p))
		goto err;
	if (!atoi(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (strlen(p) < 64)
		goto err;
	if (strspn(p, HEXCHARS_lc) != 64)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if (!isdec(p))
		goto err;
	if (!atoi(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* hash */
		goto err;
	if (strlen(p) != 64)
		goto err;
	if (strspn(p, HEXCHARS_lc) != 64)
		goto err;
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
	static pwsafe_salt *salt_struct;

	if (!salt_struct)
		salt_struct = mem_alloc(sizeof(pwsafe_salt));

	memset(salt_struct, 0, sizeof(pwsafe_salt));
	ctcopy += 9;            /* skip over "$pwsafe$*" */
	p = strtokm(ctcopy, "*");
	salt_struct->version = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < 32; i++)
		salt_struct->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	salt_struct->iterations = (unsigned int) atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < 32; i++)
		salt_struct->hash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);

	alter_endianity(salt_struct->hash, 32);

	return (void *) salt_struct;
}

static void set_salt(void *salt)
{
        memcpy(host_salt, salt, SALT_SIZE);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

        gpu_pwpass(host_pass, host_salt, host_hash, count);
        return count;
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++)
		if (host_hash[i].cracked)
			return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
        return host_hash[index].cracked;
}

static int cmp_exact(char *source, int index)
{
        return host_hash[index].cracked;
}

static void pwsafe_set_key(char *key, int index)
{
        int saved_len = MIN(strlen(key), PLAINTEXT_LENGTH);
        memcpy(host_pass[index].v, key, saved_len);
        host_pass[index].length = saved_len;
}

static char *get_key(int index)
{
        static char ret[PLAINTEXT_LENGTH + 1];
        memcpy(ret, host_pass[index].v, PLAINTEXT_LENGTH);
        ret[MIN(host_pass[index].length, PLAINTEXT_LENGTH)] = 0;
        return ret;
}

static unsigned int iteration_count(void *salt)
{
	return ((pwsafe_salt*)salt)->iterations;
}

struct fmt_main fmt_cuda_pwsafe = {
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
		KEYS_PER_CRYPT,
		KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		{
			"iteration count",
		},
		pwsafe_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		pwsafe_set_key,
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

#endif /* HAVE_CUDA */

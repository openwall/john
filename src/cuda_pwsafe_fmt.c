/* Password Safe cracker patch for JtR. Hacked together during May of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * CUDA port by Lukas Odzioba <ukasz at openwall dot net>
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "base64.h"
#include "memory.h"
#include "cuda_pwsafe.h"
#include "cuda_common.h"
#define FORMAT_LABEL            "pwsafe-cuda"
#define FORMAT_NAME             "Password Safe SHA-256"
#define ALGORITHM_NAME          "CUDA"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define PLAINTEXT_LENGTH        32
#define BINARY_SIZE             0
#define SALT_SIZE               sizeof(pwsafe_salt)
#define MIN_KEYS_PER_CRYPT      THREADS
#define MAX_KEYS_PER_CRYPT      KEYS_PER_CRYPT

static struct fmt_tests pwsafe_tests[] = {
        {"$pwsafe$*3*fefc1172093344c9d5577b25f5b4b6e5d2942c94f9fc24c21733e28ae6527521*2048*88cbaf7d8668c1a98263f5dce7cb39c3304c49a3e0d76a7ea475dc02ab2f97a7", "12345678"},
        {"$pwsafe$*3*581cd1135b9b993ccb0f6b01c1fcfacd799c69960496c96286f94fe1400c1b25*2048*4ab3c2d3af251e94eb2f753fdf30fb9da074bec6bac0fa9d9d152b95fc5795c6", "openwall"},
        {NULL}
};


static pwsafe_pass *host_pass;                          /** binary ciphertexts **/
static pwsafe_salt *host_salt;                          /** salt **/
static pwsafe_hash *host_hash;                          /** calculated hashes **/
extern void gpu_pwpass(pwsafe_pass *, pwsafe_salt *, pwsafe_hash *, int count);

static void done()
{
	MEM_FREE(host_salt);
	MEM_FREE(host_hash);
	MEM_FREE(host_pass);
}

static void init(struct fmt_main *self)
{
        host_pass = mem_calloc(KEYS_PER_CRYPT * sizeof(pwsafe_pass));
        host_hash = mem_calloc(KEYS_PER_CRYPT * sizeof(pwsafe_hash));
        host_salt = mem_calloc(sizeof(pwsafe_salt));
	cuda_init(cuda_gpu_id);
        atexit(done);
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
	if ((p = strtok(ctcopy, "*")) == NULL)	/* version */
		goto err;
	if (atoi(p) == 0)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (strlen(p) < 64)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if (atoi(p) == 0)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* hash */
		goto err;
	if (strlen(p) != 64)
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
        pwsafe_salt *salt_struct =
            mem_alloc_tiny(sizeof(pwsafe_salt), MEM_ALIGN_WORD);
	ctcopy += 9;            /* skip over "$pwsafe$*" */
        p = strtok(ctcopy, "*");
        salt_struct->version = atoi(p);
        p = strtok(NULL, "*");
        for (i = 0; i < 32; i++)
                salt_struct->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
                    + atoi16[ARCH_INDEX(p[i * 2 + 1])];
        p = strtok(NULL, "*");
        salt_struct->iterations = (unsigned int) atoi(p);
        p = strtok(NULL, "*");
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

static void crypt_all(int count)
{
	gpu_pwpass(host_pass, host_salt, host_hash, count);
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
        int saved_key_length = MIN(strlen(key), PLAINTEXT_LENGTH);
        memcpy(host_pass[index].v, key, saved_key_length);
        host_pass[index].length = saved_key_length;
}

static char *get_key(int index)
{
        static char ret[PLAINTEXT_LENGTH + 1];
        memcpy(ret, host_pass[index].v, PLAINTEXT_LENGTH);
        ret[MIN(host_pass[index].length, PLAINTEXT_LENGTH)] = 0;
        return ret;
}

struct fmt_main fmt_cuda_pwsafe = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		KEYS_PER_CRYPT,
		KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		pwsafe_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
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

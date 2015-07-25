/*
* This software is Copyright (c) 2012 Lukas Odzioba <lukas dot odzioba at gmail dot com>
* and Copyright (c) 2013-2014 magnum
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifdef HAVE_CUDA

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cuda_wpapsk;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cuda_wpapsk);
#else

#include <string.h>
#include <assert.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_wpapsk.h"
#include "cuda_common.h"
#include "memdbg.h"

#define FORMAT_LABEL		"wpapsk-cuda"
#define FORMAT_NAME		"WPA/WPA2 PSK"
#define ALGORITHM_NAME		"PBKDF2-SHA1 CUDA"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1

///#define WPAPSK_DEBUG
extern wpapsk_password *inbuffer;
extern wpapsk_hash *outbuffer;
extern wpapsk_salt currentsalt;
extern hccap_t hccap;
extern mic_t *mic;
extern void wpapsk_gpu(wpapsk_password *, wpapsk_hash *, wpapsk_salt *, int);

extern void *get_salt(char *ciphertext);

static void done(void)
{
	MEM_FREE(inbuffer);
	MEM_FREE(outbuffer);
	MEM_FREE(mic);
}

static void init(struct fmt_main *self)
{
	///Allocate memory for hashes and passwords
	inbuffer =
		(wpapsk_password *) mem_calloc(MAX_KEYS_PER_CRYPT,
		                               sizeof(wpapsk_password));
	outbuffer =
	    (wpapsk_hash *) mem_alloc(MAX_KEYS_PER_CRYPT * sizeof(wpapsk_hash));
	check_mem_allocation(inbuffer, outbuffer);
	mic = (mic_t *) mem_alloc(MAX_KEYS_PER_CRYPT * sizeof(mic_t));
	///Initialize CUDA
	cuda_init();
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

	if (new_keys || strcmp(last_ssid, hccap.essid)) {
		wpapsk_gpu(inbuffer, outbuffer, &currentsalt, count);
		new_keys = 0;
		strcpy(last_ssid, hccap.essid);
	}

	wpapsk_postprocess(count);
	return count;
}

struct fmt_main fmt_cuda_wpapsk = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		8,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_OMP,
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
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		salt_compare,
		set_salt,
		set_key,
		get_key,
		clear_keys,
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

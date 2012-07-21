/*
* This software is Copyright (c) 2012 Lukas Odzioba <lukas dot odzioba at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#include <string.h>
#include "arch.h"
#include <assert.h>
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_wpapsk.h"
#include "cuda_common.h"

#define FORMAT_LABEL		"wpapsk-cuda"
#define FORMAT_NAME		"WPA-PSK PBKDF2-HMAC-SHA-1"
#define ALGORITHM_NAME		"CUDA"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1

///#define WPAPSK_DEBUG
extern wpapsk_password *inbuffer;
extern wpapsk_hash *outbuffer;
extern wpapsk_salt currentsalt;
extern hccap_t hccap;
extern mic_t *mic;
extern void wpapsk_gpu(wpapsk_password *, wpapsk_hash *, wpapsk_salt *);

extern void *salt(char *ciphertext);

/** testcase from http://wiki.wireshark.org/SampleCaptures = wpa-Induction.pcap **/
static struct fmt_tests wpapsk_tests[] = {
	{"$WPAPSK$Coherer#..l/Uf7J..qHUXMunTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosMyXdNxfBZUAYmgKqeb6GBPxLiIZr56NtWTGR/Cp5ldAk61.5I0.Ec.2...........nTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosM.................................................................3X.I.E..1uk0.E..1uk2.E..1uk0....................................................................................................................................................................................../t.....U...8FWdk8OpPckhewBwt4MXYI", "Induction"},
	{NULL}
};


static void cleanup()
{
	free(inbuffer);
	free(outbuffer);
	free(mic);
}

static void init(struct fmt_main *pFmt)
{
	assert(sizeof(hccap_t) == HCCAP_SIZE);
	///Alocate memory for hashes and passwords
	inbuffer =
	    (wpapsk_password *) malloc(sizeof(wpapsk_password) *
	    MAX_KEYS_PER_CRYPT);
	outbuffer =
	    (wpapsk_hash *) malloc(sizeof(wpapsk_hash) * MAX_KEYS_PER_CRYPT);
	check_mem_allocation(inbuffer, outbuffer);
	mic = (mic_t *) malloc(sizeof(mic_t) * MAX_KEYS_PER_CRYPT);
	atexit(cleanup);

/*
 * Zeroize the lengths in case crypt_all() is called with some keys still
 * not set.  This may happen during self-tests.
 */
	{
		int i;
		for (i = 0; i < pFmt->params.max_keys_per_crypt; i++)
			inbuffer[i].length = 0;
	}

	///Initialize CUDA
	cuda_init(gpu_id);
}

static void crypt_all(int count)
{
	wpapsk_gpu(inbuffer, outbuffer, &currentsalt);
	wpapsk_postprocess(KEYS_PER_CRYPT);
}

struct fmt_main fmt_cuda_wpapsk = {
	{
		    FORMAT_LABEL,
		    FORMAT_NAME,
		    ALGORITHM_NAME,
		    BENCHMARK_COMMENT,
		    BENCHMARK_LENGTH,
		    PLAINTEXT_LENGTH,
		    BINARY_SIZE,
		    SALT_SIZE,
		    MIN_KEYS_PER_CRYPT,
		    MAX_KEYS_PER_CRYPT,
		    FMT_CASE | FMT_8_BIT | FMT_OMP,
	    wpapsk_tests},
	{
		    init,
		    fmt_default_prepare,
		    valid,
		    fmt_default_split,
		    binary,
		    salt,
		    {
				binary_hash_0,
				binary_hash_1,
				binary_hash_2,
				binary_hash_3,
				binary_hash_4,
				binary_hash_5,
			binary_hash_6},
		    fmt_default_salt_hash,
		    set_salt,
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
			get_hash_6},
		    cmp_all,
		    cmp_one,
	    cmp_exact}
};

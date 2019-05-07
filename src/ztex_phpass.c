/*
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2008,2010-2013,2015 by Solar Designer
 *
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2012 magnum / JimF
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 */
#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "common.h"
#include "formats.h"
#include "memory.h"
#include "config.h"
#include "options.h"
#include "phpass_common.h"

#include "ztex/device_bitstream.h"
#include "ztex/device_format.h"
#include "ztex/task.h"
#include "ztex/pkt_comm/cmp_config.h"


#define FORMAT_LABEL		"phpass-ztex"
#define ALGORITHM_NAME		"phpass ($P$ or $H$)"

#define FORMAT_NAME		""

#define BENCHMARK_COMMENT	""

#undef PLAINTEXT_LENGTH
#define PLAINTEXT_LENGTH	64

// Partial hash in the database - differs from CPU/GPU implementations
#undef	BINARY_SIZE
#define	BINARY_SIZE		4

// Actual salt size is 9
#define	SALT_SIZE		8
#define	SALT_ALIGN		1


static struct device_bitstream bitstream = {
	// bitstream ID (check is performed by querying operating bitstream)
	0xd5c0,
	"$JOHN/ztex/ztex115y_md5crypt.bit",
	// parameters for high-speed packet communication (pkt_comm)
	{ 2, 14336, 4094 },
	// computing performance estimation (in candidates per interval)
	// (keys * mask_num_cand)/crypt_all_interval per jtr_device.
	1,		// keys/fpga for crypt_all(): set by init()
	4096,	// keys/fpga for self-test
	600*1024,	// Would be ~20 MB of USB traffic on 32-byte keys
	512,		// Max. number of entries in onboard comparator.
	32*12,		// Min. number of keys for effective device utilization
	0,
	1, { 180 },	// Programmable clocks
	"phpass",	// label for configuration file
	"\x01", 1	// Initialization data
};


static int target_rounds;

static void init(struct fmt_main *fmt_main)
{
	//
	// It gets TargetRounds from john.conf and adjust
	// bitstream.candidates_per_crypt.

	// Starting from TARGET_ROUNDS_1KPC, it sets keys_per_crypt
	// equal to bitstream.min_keys
	//
	const int TARGET_ROUNDS_1KPC = 384*1024;

	target_rounds = cfg_get_int("ZTEX:", bitstream.label,
			"TargetRounds");
	if (target_rounds <= 0)
		target_rounds = 2048;

	if (target_rounds < 512) {
		fprintf(stderr, "Warning: invalid TargetRounds=%d in john.conf."
			" Valid values are 512-1048576, must be power of 2\n",
			target_rounds);
		target_rounds = 512;
	}

	if (target_rounds >= TARGET_ROUNDS_1KPC)
		bitstream.candidates_per_crypt = bitstream.min_keys;
	else
		bitstream.candidates_per_crypt = bitstream.min_keys
			* (2 * TARGET_ROUNDS_1KPC / target_rounds);

	device_format_init(fmt_main, &bitstream, options.acc_devices,
		options.verbosity);
}


/*
 * There's an existing CPU implementation. It stores salt in the database.
 * 1) Salt data structure db_salt->salt is specific to algorithm
 * 2) db_salt->salt depends on host system (e.g. different on 32 and 64-bit)
 * 3) This salt internally has tunable costs and is used to
 * populate db_salt->cost[FMT_TUNABLE_COSTS].
 *
 * Salt is sent to devices in some uniform way in CMP_CONFIG packet:
 * - first it goes binary salt in network byte order
 * - then it sends 4-byte tunable cost(s) if any
 * - then it sends 2 bytes - number of hashes
 * - then partial hashes ("binaries") sorted in ascending order.
 * (It accepts up to 512 32-bit hashes, order doesn't matter).
 */

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int result;
	unsigned char salt_buf[18]; // salt to send to device
	int salt_len;
	static int warning_target_rounds = 0;

	int curr_rounds = phpass_common_iteration_count(salt->salt);

	if (!warning_target_rounds && !bench_or_test_running
			&& (curr_rounds > target_rounds * 2
			|| curr_rounds < target_rounds / 2)
	) {
		fprintf(stderr, "Warning: TargetRounds=%d, processing"
			" hash with rounds=%d, expecting suboptimal performance or"
			" timeout, consider to adjust TargetRounds in john.conf\n",
			target_rounds, curr_rounds);
		warning_target_rounds = 1;
	}

	salt_len = strnlen(salt->salt, 8);

	// 1 byte unused, 1 byte salt_len, 16 bytes salt in network byte order
	salt_buf[0] = 0;
	salt_buf[1] = salt_len;
	memcpy(salt_buf + 2, salt->salt, salt_len);

	cmp_config_new(salt, salt_buf, 18);

	result = device_format_crypt_all(pcount, salt);
	return result;
}


static void *get_salt(char *ciphertext)
{
	static union {
		unsigned char salt[SALT_SIZE+2];
		uint32_t dummy[(SALT_SIZE+2+sizeof(uint32_t)-1)/sizeof(uint32_t)];
	} x;
	unsigned char *salt = x.salt;

	// store off the 'real' 8 bytes of salt
	memcpy(salt, &ciphertext[4], 8);
	// append the 1 byte of loop count information.
	salt[8] = ciphertext[3];
	salt[9]=0;
	return salt;
}


extern struct task_list *task_list;

static int cmp_exact(char *source, int index)
{
	struct task_result *result = task_result_by_index(task_list, index);
/*
	fprintf(stderr,"cmp_exact index %d, key '%s'\n",index,result->key);
	int i;
	for (i=0; i < 16; i++)
		fprintf(stderr,"%02x ", result->binary[i]);
	fprintf(stderr,"\n");
	for (i=0; i < 16; i++)
		fprintf(stderr,"%02x ", (((char *)get_binary(source)) + i)[0] & 0xFF);
	fprintf(stderr,"\n");
*/
	return !memcmp(result->binary, phpass_common_binary(source), 16);
}


struct fmt_main fmt_ztex_phpass = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH | 0x100,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE + 1,
		SALT_ALIGN,
		1, // set by device_format_reset()
		1,
		FMT_CASE | FMT_8_BIT | FMT_MASK,
		{
			"iteration count",
		},
		{ FORMAT_TAG, FORMAT_TAG2, FORMAT_TAG3 },
		phpass_common_tests
	}, {
		init,
		device_format_done,
		device_format_reset,
		phpass_common_prepare,
		phpass_common_valid,
		phpass_common_split,
		phpass_common_binary,
		get_salt,
		{
			phpass_common_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		device_format_set_salt,
		device_format_set_key,
		device_format_get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			device_format_get_hash_0,
			device_format_get_hash_1,
			device_format_get_hash_2,
			device_format_get_hash_3,
			device_format_get_hash_4,
			device_format_get_hash_5,
			device_format_get_hash_6
		},
		device_format_cmp_all,
		device_format_cmp_one,
		cmp_exact
	}
};

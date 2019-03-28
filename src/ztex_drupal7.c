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
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */
#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "common.h"
#include "formats.h"
#include "memory.h"
#include "config.h"
#include "options.h"

#include "ztex/device_bitstream.h"
#include "ztex/device_format.h"
#include "ztex/task.h"
#include "ztex/pkt_comm/cmp_config.h"

#include "drupal7_common.h"

#define FORMAT_LABEL			"Drupal7-ztex"
#define ALGORITHM_NAME		"SHA512 ZTEX"

#define PLAINTEXT_LENGTH	64
#define BINARY_SIZE			4
#define BINARY_ALIGN		4


static struct device_bitstream bitstream = {
	// bitstream ID (check is performed by querying operating bitstream)
	0x512c,
	"$JOHN/ztex/ztex115y_sha512crypt.bit",
	// parameters for high-speed packet communication (pkt_comm)
	{ 2, 6144, 8190 },
	// computing performance estimation (in candidates per interval)
	// (keys * mask_num_cand)/crypt_all_interval per jtr_device.
	1,			// set by init()
	1024,		// 1K keys/fpga for self-test
	512 * 1024,	// Absolute max. keys/crypt_all_interval for all devices.
	512,		// Max. number of entries in onboard comparator.
	12 * 16,	// Min. number of keys for effective device utilization
	0,
	1, { 160 },	// Programmable clocks
	"Drupal7",	// label for configuration file
	"\x01", 1	// Initialization data
};


static int target_rounds;

static void init(struct fmt_main *fmt_main)
{
	// It uses performance estimation (bitstream.candidates_per_crypt)
	// to calculate keys_per_crypt. Performance depends on count of rounds.
	// Count is not available in init() and can change at runtime.
	// In crypt_all(), count is available but keys_per_crypt can't change.
	//
	// It gets TargetRounds from john.conf and adjust
	// bitstream.candidates_per_crypt.

	// Starting from TARGET_ROUNDS_1KPC, it sets keys_per_crypt
	// equal to bitstream.min_keys
	//
	const int TARGET_ROUNDS_1KPC = 256*1024;

	target_rounds = cfg_get_int("ZTEX:", bitstream.label,
			"TargetRounds");
	if (target_rounds <= 0)
		target_rounds = 16384;

	if (target_rounds < 1000)
		fprintf(stderr, "Warning: invalid TargetRounds=%d in john.conf."
			" Valid values are 1000-999999999\n", target_rounds);

	if (target_rounds < 1000)
		target_rounds = 1000;

	if (target_rounds >= TARGET_ROUNDS_1KPC)
		bitstream.candidates_per_crypt = bitstream.min_keys;
	else
		bitstream.candidates_per_crypt = bitstream.min_keys
			* (2 * TARGET_ROUNDS_1KPC / target_rounds);

	//fprintf(stderr, "bitstream.candidates_per_crypt=%d\n",
	//		bitstream.candidates_per_crypt);

	device_format_init(fmt_main, &bitstream, options.acc_devices,
		options.verbosity);
}



static int crypt_all(int *pcount, struct db_salt *salt)
{
	int result;
	static int warning_target_rounds = 0;
	int curr_rounds = salt->cost[0];

	unsigned char salt_buf[18]; // salt to send to device

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

	// 1 byte unused, 1 byte salt_len, 16 bytes salt in network byte order
	salt_buf[0] = 0;
	salt_buf[1] = 8;
	memcpy(salt_buf + 2, salt->salt, 8);
	memset(salt_buf + 10, 0, 8);

	cmp_config_new(salt, salt_buf, 18);

	result = device_format_crypt_all(pcount, salt);
	return result;
}


extern struct task_list *task_list;

static int cmp_exact(char *source, int index)
{
	struct task_result *result = task_result_by_index(task_list, index);

	//fprintf(stderr,"cmp_exact start %d, key %s\n",index,result->key);

	return !memcmp(result->binary, get_binary(source), 32);
}


struct fmt_main fmt_ztex_drupal7 = {
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
		SALT_SIZE + 1,
		SALT_ALIGN,
		1, // set by device_format_reset()
		1,
		FMT_CASE | FMT_8_BIT | FMT_MASK,
		{
			"iteration count",
		},
		{
			FORMAT_TAG
		},
		tests
	}, {
		init,
		device_format_done,
		device_format_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			iteration_count,
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
		salt_hash,
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

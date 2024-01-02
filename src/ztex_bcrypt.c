/*
 * This software is Copyright (c) 2016-2017,2019 Denis Burykin
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

#include "BF_common.h"

#include "ztex/device_bitstream.h"
#include "ztex/device_format.h"
#include "ztex/task.h"
#include "ztex/pkt_comm/cmp_config.h"
#include "ztex/jtr_device.h"


#define FORMAT_LABEL			"bcrypt-ztex"
#define FORMAT_NAME				""
#define ALGORITHM_NAME			"Blowfish ZTEX"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0x107

#define PLAINTEXT_LENGTH		72

// Binary and salt: stored exactly as in CPU implementation
#define BINARY_SIZE				4
#define BINARY_ALIGN			4
#define SALT_SIZE				sizeof(BF_salt)
#define SALT_ALIGN				4


static struct device_bitstream bitstream = {
	// bitstream ID (check is performed by querying operating bitstream)
	0xbc01,
	"$JOHN/ztex/ztex115y_bcrypt.bit",
	// parameters for high-speed packet communication (pkt_comm)
	{ 2, 6144, 8190 },
	// computing performance estimation (in candidates per interval)
	// (keys * mask_num_cand)/crypt_all_interval per jtr_device.
	1,			// set by init()
	2048,		// 2K keys per FPGA for self-test.
	// Absolute max. keys/crypt_all_interval for all devices.
	512 * 1024,	// Would be 36MB of USB traffic on 72-byte keys
	512,		// Max. number of entries in onboard comparator.
	124,		// Min. number of keys for effective device utilization
	0,
	1, { 150 },	// Programmable clocks
	"bcrypt",	// label for configuration file
	NULL, 0		// Initialization data
};


static struct fmt_tests tests[] = {

	{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK",
		"U*U*"},
	// 32 lower bits of hash are equal to the above hash - self-test fails.
	// In formats.c:is_key_right() it takes the first index for which
	// cmp_one() returns true, and expects cmp_exact() also to return true
	// for that index which is the case in CPU version.
	// Here results arrive in the reverse order and it fails.
	//{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzAxtE4OUcU.5p75hOF2yn2i1ocvO",
	//	"1E!dpr"},
	{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy",
		""},
	{"$2b$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a",
		"U*U*U"},
	{"$2a$08$CCCCCCCCCCCCCCCCCCCCC.LuntE/dBezheibpSOXBeR3W7q5mt2NW",
		">RQ7la"},

	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6",
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"chars after 72 are ignored as usual"},
	{"$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy",
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"},
	{"$2x$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e",
		"\xa3"},
	{"$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq",
		"\xa3"},

	{"$2x$05$6bNw2HLQYeqHYyBfLMsv/OiwqTymGIGzFsA4hOTWebfehXHNprcAS",
		"\xd1\x91"},
	{"$2x$05$6bNw2HLQYeqHYyBfLMsv/O9LIGgn8OMzuDoHfof8AQimSGfcSWxnS",
		"\xd0\xc1\xd2\xcf\xcc\xd8"},

	{"$2a$04$pIqNJ/d3.iUtNb........1ynmOuHkBNwBW8zbBj6wTB8XX4/HPiy",
		"01234567"},
	{"$2a$04$pIqNJ/d3.iUtNb........12LxxKuTok3B2V5Qedwkj.KlH.1uvye",
		"012345678"},
	{"$2a$04$pIqNJ/d3.iUtNb........UNDUi60rNJGFKeSG7vI091NbSOdQNfa",
		"0123456789"},
	{NULL}
};


int target_setting;

static void init(struct fmt_main *fmt_main)
{
	// It uses performance estimation (bitstream.candidates_per_crypt)
	// to calculate keys_per_crypt. Performance depends on setting.
	// Setting is not available in init() and can change at runtime.
	// In crypt_all(), setting is available but keys_per_crypt can't change.
	//
	// It gets TargetSetting from john.conf and adjust
	// bitstream.candidates_per_crypt.
	//
	if ((target_setting = cfg_get_int("ZTEX:", bitstream.label,
	                                  "TargetSetting")) <= 0)
		target_setting = 8;

	if (target_setting < 5 || target_setting > 19) {
		fprintf(stderr, "Warning: invalid TargetSetting=%d in john.conf."
			" Valid values are 5-19\n", target_setting);
		if (target_setting < 5)
			target_setting = 5;
		else if (target_setting > 19)
			target_setting = 19;
	}

	bitstream.candidates_per_crypt = bitstream.min_keys;

	// It computes a hash with setting 13 in ~1s
	if (target_setting < 13)
		bitstream.candidates_per_crypt *= (1 << (13 - target_setting));

	//fprintf(stderr, "bitstream.candidates_per_crypt=%d\n",
	//		bitstream.candidates_per_crypt);

	device_format_init(fmt_main, &bitstream, options.acc_devices,
		options.verbosity);
}

// Existing CPU implementation use following data structures:
//
// typedef ARCH_WORD_32 BF_word;
//
// typedef BF_word BF_binary[6]; <-- 24 bytes, OK
//
// typedef struct {
//	BF_word salt[4];
//	unsigned char rounds;
//	char subtype;
//} BF_salt;
//

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
 * - then partial hashes ("binaries") sorted in ascending order. (bcrypt-ztex
 *   accepts up to 'cmp_entries_max' 32-bit hashes, order doesn't matter).
 *
 */


static int get_setting_by_cost(int cost)
{
	int setting = 0;
	for (; cost > 1; cost /= 2)
		setting++;
	return setting;
}


extern int device_nocompar_mode;

// TODO: handle BE systems
static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i, result, curr_setting;
	static int warning_curr_setting16 = 0;
	static int warning_target_setting = 0;

	static unsigned char salt_buf[17]; // salt to send to device
	BF_salt *BF_salt = salt->salt;

	if (salt->count > bitstream.cmp_entries_max && !device_nocompar_mode) {
		fprintf(stderr, "Warning: salt with %d hashes, onboard comparators "
			"support up to %d hashes/salt, turned off\n",
			salt->count, bitstream.cmp_entries_max);
		jtr_device_list_set_app_mode(0x40);
		device_nocompar_mode = 1;
	}

	// It requires 16 bytes salt and 1 char subtype in network byte order
	for (i = 0; i < 4; i++)
		((uint32_t *)(salt_buf))[i] = BF_salt->salt[i];
	salt_buf[16] = BF_salt->subtype;

	if (device_nocompar_mode)
		cmp_config_nocompar_new(salt, salt_buf, 17);
	else
		cmp_config_new(salt, salt_buf, 17);

	curr_setting = get_setting_by_cost(salt->cost[0]);

	if (!warning_curr_setting16 && curr_setting >= 16) {
		fprintf(stderr, "Warning: hash with setting=%d, computation"
			" is going to be very slow, timeout is possible,"
			" consider to increase"
			" device_format.c:DEVICE_TASK_TIMEOUT\n", curr_setting);
		fprintf(stderr, "Recommended DEVICE_TASK_TIMEOUT value for"
			" setting %d: %d\n", curr_setting,
			curr_setting == 16 ? 10 :
			curr_setting == 17 ? 20 :
			curr_setting == 18 ? 35 :
			70);
		warning_curr_setting16 = 1;
	}

	if (!warning_target_setting && !bench_or_test_running
			&& (curr_setting > target_setting + 2
			|| curr_setting < target_setting - 2)
	) {
		fprintf(stderr, "Warning: TargetSetting=%d, processing"
			" hash with setting=%d, expecting suboptimal performance or"
			" timeout, consider to adjust TargetSetting in john.conf\n",
			target_setting, curr_setting);
		warning_target_setting = 1;
	}

	result = device_format_crypt_all(pcount, salt);
	return result;
}


static int salt_hash(void *salt)
{
	return ((BF_salt *)salt)->salt[0] & (SALT_HASH_SIZE - 1);
}


extern struct task_list *task_list;

static int cmp_exact(char *source, int index)
{
	struct task_result *result = task_result_by_index(task_list, index);

	//fprintf(stderr,"cmp_exact start %d, key %s\n",index,result->key);

	// Implementation feature: Byte 20 is zero
	result->binary[20] = 0x00;

	return !memcmp(result->binary, BF_common_get_binary(source), 24);
}


struct fmt_main fmt_ztex_bcrypt = {
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
		1,
		1,
		FMT_CASE | FMT_8_BIT | FMT_TRUNC | FMT_MASK,
		{
			"iteration count",
		},
		{
			FORMAT_TAG,
			FORMAT_TAG2,
			FORMAT_TAG3,
			FORMAT_TAG4
		},
		tests
	}, {
		init,
		device_format_done,
		device_format_reset,
		fmt_default_prepare,
		BF_common_valid,
		BF_common_split,
		BF_common_get_binary,
		BF_common_get_salt,
		{
			BF_common_iteration_count,
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

/*
 * This software is Copyright (c) 2018-2019 Denis Burykin
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
#include "MD5_std.h"
#include "md5crypt_common.h"

#include "ztex/device_bitstream.h"
#include "ztex/device_format.h"
#include "ztex/task.h"
#include "ztex/pkt_comm/cmp_config.h"


#define FORMAT_LABEL		"md5crypt-ztex"
#define ALGORITHM_NAME		"md5crypt ZTEX"

#define FORMAT_NAME		"crypt(3) $1$"
#define FORMAT_TAG			"$1$"
#define FORMAT_TAG_LEN		(sizeof(FORMAT_TAG)-1)

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0x107

#define CIPHERTEXT_LENGTH		22

// Data structures differ from ones from CPU implementation:
// - Only partial hash in the database (BINARY_SIZE=4)
// - The hardware allows candidate length <= 64
//
#define PLAINTEXT_LENGTH	64
#define BINARY_SIZE			4
#define BINARY_ALIGN		4
#define SALT_SIZE			9
#define SALT_ALIGN			1


static struct device_bitstream bitstream = {
	// bitstream ID (check is performed by querying operating bitstream)
	0xd5c0,
	"$JOHN/ztex/ztex115y_md5crypt.bit",
	// parameters for high-speed packet communication (pkt_comm)
	{ 2, 14336, 4094 },
	// computing performance estimation (in candidates per interval)
	// (keys * mask_num_cand)/crypt_all_interval per jtr_device.
	32*12*640,	// keys/fpga for crypt_all()
	8192,		// keys/fpga for self-test
	600*1024,	// Would be ~20 MB of USB traffic on 32-byte keys
	512,		// Max. number of entries in onboard comparator.
	32*12,		// Min. number of keys for effective device utilization
	0,
	1, { 180 },	// Programmable clocks
	"md5crypt",	// label for configuration file
	"\x00", 1	// Initialization data
};


static struct fmt_tests tests[] = {
	{"$1$12345678$aIccj83HRDBo6ux1bVx7D1", "0123456789ABCDE"},
	{"$1$12345678$f8QoJuo0DpBRfQSD0vglc1", "12345678"},
	{"$1$1234$BdIMOAWFOV2AQlLsrN/Sw.", "1234"},
	{"$1$bb$19smCEBG0Q1pVil0/HqK./", "aaaaa"},
	{"$1$coin$rebm0t9KJ56mgGWJF5o5M0", "lapin"},
	{"$1$pouet$/Ecz/vyk.zCYvrr6wB78h0", "canard"},
	{"$1$test2$02MCIATVoxq3IhgK6XRkb1", "test1"},
	{"$1$aussi$X67z3kXsWo92F15uChx1H1", "felicie"},
	{"$1$boire$gf.YM2y3InYEu9.NbVr.v0", "manger"},
	{"$1$bas$qvkmmWnVHRCSv/6LQ1doH/", "haut"},
	{"$1$gauche$EPvd6LZlrgb0MMFPxUrJN1", "droite"},
	{"$1$qxBtihlm$YDZLjH2jPh5FsbPoo7D5j/", "\xc0\xc1\xc2\xc3"},

	// key_len > 15
	{"$1$fG07tEwk$0vSr/Hg/.l01NgYWr8aSB.", "1234567890ABCDEF"},
	{"$1$fkEasaUI$G7CelOWHkol2nVHN8XQP40", "aaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$12345678$/Y8HRXkjaI0wpCjIOG1xv1", "key_len=31..................../"},
	{"$1$12345678$YwDJjafnp9d0vGAuGWwaK/", "key_len=32...................../"},
	{"$1$IsuapfCX$4Yq0Adq5nNZgl0LwbSl5Y0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$rSZfNcKX$N4XPvGrfhKsyoEcRSaqmG0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$abcd0000$nNTpR9XboutDDILjNSXMC/",
		"key_len=64.....567890123456789012345678901234567890123456789abcd"},
	{NULL}
};


static int cryptmd5_common_valid_salt0(char *ciphertext, struct fmt_main *self)
{
	char *pos, *start;
	char *salt_pos, *salt_end_pos;

	if (!strncmp(ciphertext, md5_salt_prefix, md5_salt_prefix_len))
		ciphertext += md5_salt_prefix_len;
	else if (!strncmp(ciphertext, apr1_salt_prefix, apr1_salt_prefix_len))
		ciphertext += apr1_salt_prefix_len;
	else if (!strncmp(ciphertext, smd5_salt_prefix, smd5_salt_prefix_len))
		ciphertext += smd5_salt_prefix_len;
	else
		return 0;

	salt_pos = ciphertext;
	for (pos = ciphertext; *pos && *pos != '$'; pos++);
	if (!*pos || pos < ciphertext || pos > &ciphertext[11]) return 0;
	salt_end_pos = pos;

	start = ++pos;
	while (atoi64[ARCH_INDEX(*pos)] != 0x7F) pos++;
	if (*pos || pos - start != 22) return 0;

	if (atoi64[ARCH_INDEX(*(pos - 1))] & 0x3C) return 0;
	if (salt_end_pos == salt_pos) {
		printf("Warning: ZTEX: md5crypt hash with salt_length=0 skipped.\n");
		return 0;
	}
	return 1;
}

static void init(struct fmt_main *fmt_main)
{
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
	unsigned char salt_buf[22]; // salt to send to device

	int salt_len = strnlen(salt->salt, 8);

	// 1 byte unused, 1 byte salt_len, 16 bytes salt in network byte order
	salt_buf[0] = 0;
	salt_buf[1] = salt_len;
	memcpy(salt_buf + 2, salt->salt, salt_len);
	// The device expects salt (18 bytes) then 4 bytes for each
	// "tunable cost", for those found in struct fmt_main.
	// We add-up "tunable cost" of 1,000 like if it was in "struct fmt_main".
	salt_buf[18] = 1000 % 256;
	salt_buf[19] = 1000 / 256;
	salt_buf[20] = 0;
	salt_buf[21] = 0;

	cmp_config_new(salt, salt_buf, 22);

	result = device_format_crypt_all(pcount, salt);
	return result;
}


static void *get_salt(char *ciphertext) {
	return MD5_std_get_salt(ciphertext);
}

static void *get_binary(char *ciphertext) {
	return MD5_std_get_binary(ciphertext);
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
	return !memcmp(result->binary, get_binary(source), 16);
}


struct fmt_main fmt_ztex_md5crypt = {
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
		1, // set by device_format_reset()
		1,
		FMT_CASE | FMT_8_BIT | FMT_MASK,
		{NULL},
		{
			FORMAT_TAG
		},
		tests
	}, {
		init,
		device_format_done,
		device_format_reset,
		fmt_default_prepare,
		cryptmd5_common_valid_salt0,
		fmt_default_split,
		get_binary,
		get_salt,
		{NULL},
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

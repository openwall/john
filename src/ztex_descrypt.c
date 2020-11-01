/*
 * This software is Copyright (c) 2016-2017,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Used functions from DES implementation, John the Ripper password cracker
 * Copyright (c) 1996-2001,2005,2012 by Solar Designer
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */
#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "common.h"
#include "formats.h"
#include "memory.h"
#include "options.h"
#include "DES_std.h"

#include "ztex/device_bitstream.h"
#include "ztex/device_format.h"
#include "ztex/task.h"
#include "ztex/pkt_comm/cmp_config.h"


#define FORMAT_LABEL			"descrypt-ztex"
#define FORMAT_NAME				"traditional crypt(3)"
#define ALGORITHM_NAME			"DES ZTEX"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0x107

#define PLAINTEXT_LENGTH		8

// * Binary and salt are stored in network byte order.
// * 35-bit partial binary. Upper bits of the last byte are 0.
#define BINARY_SIZE				5
#define BINARY_ALIGN			1
#define BINARY_LAST_BYTE_MASK	0x07
#define SALT_SIZE				2
#define SALT_ALIGN				1


struct device_bitstream bitstream = {
	// bitstream ID (check is performed by querying operating bitstream)
	0x0101,
	"$JOHN/ztex/ztex115y_descrypt.bit",
	// parameters for high-speed packet communication (pkt_comm)
	{ 2, 32768, 2046 },
	// computing performance estimation (in candidates per interval)
	// (keys * mask_num_cand)/crypt_all_interval per jtr_device.
	200 * 1024*1024,
	32 * 1024,	// 32K keys for each FPGA for self-test
	// Absolute max. keys/crypt_all_interval for all devices.
	1024*1024,	// ~8 MB of USB traffic
	// Max. number of entries in onboard comparator.
	2047,
	0,	// Min. number of keys (doesn't matter for fast "formats")
	32,	// Min. template keys (e.g. several generators)
	1, { 190 },	// Programmable clocks
	"descrypt",	// label for configuration file
	NULL, 0		// Initialization data
};


static struct fmt_tests tests[] = {
	{"CCNf8Sbh3HDfQ", "U*U*U*U*"},
	{"CCX.K.MFy4Ois", "U*U***U"},
	{"CC4rMpbg9AMZ.", "U*U***U*"},
	{"XXxzOu6maQKqQ", "*U*U*U*U"},
	{"SDbsugeBiC58A", ""},
	{"bbc1MMnm9AB52", "########"},
	{"zzfERZdZxZJeg", "11111111"},
	{"..4Xmrg11Z3jU", "00000000"},
	{"////////FevBg", "-/<0S]"},
	{"///.......Lb2", "i*]cYae"},
	{"//..////..8/c", "#?Ez|?r"},
	{"35LSBeq/uVetI", "==*d2{^6"},

	// These cause self-test to fail:
	// cmp_one() returns true and cmp_exact() returns false
	// because of partial binaries in the comparator
	//
	//{"35LSBeq.RUJA.", "==tCG*l2"},
	//{"35LSBeq.Xbkho", "==*]fyOo"},
	{NULL}
};

#define CIPHERTEXT_LENGTH_1		13
#define CIPHERTEXT_LENGTH_2		24


static unsigned char DES_atoi64_bitswapped[128] = {
	0x12, 0x32, 0x0a, 0x2a, 0x1a, 0x3a, 0x06, 0x26,
	0x16, 0x36, 0x0e, 0x2e, 0x1e, 0x3e, 0x01, 0x21,
	0x11, 0x31, 0x09, 0x29, 0x19, 0x39, 0x05, 0x25,
	0x15, 0x35, 0x0d, 0x2d, 0x1d, 0x3d, 0x03, 0x23,
	0x13, 0x33, 0x0b, 0x2b, 0x1b, 0x3b, 0x07, 0x27,
	0x17, 0x37, 0x0f, 0x2f, 0x1f, 0x3f, 0x00, 0x20,
	0x10, 0x30, 0x08, 0x28, 0x18, 0x38, 0x04, 0x24,
	0x14, 0x34, 0x28, 0x18, 0x38, 0x04, 0x24, 0x14,
	0x34, 0x0c, 0x2c, 0x1c, 0x3c, 0x02, 0x22, 0x12,
	0x32, 0x0a, 0x2a, 0x1a, 0x3a, 0x06, 0x26, 0x16,
	0x36, 0x0e, 0x2e, 0x1e, 0x3e, 0x01, 0x21, 0x11,
	0x31, 0x09, 0x29, 0x01, 0x21, 0x11, 0x31, 0x09,
	0x29, 0x19, 0x39, 0x05, 0x25, 0x15, 0x35, 0x0d,
	0x2d, 0x1d, 0x3d, 0x03, 0x23, 0x13, 0x33, 0x0b,
	0x2b, 0x1b, 0x3b, 0x07, 0x27, 0x17, 0x37, 0x0f,
	0x2f, 0x1f, 0x3f, 0x00, 0x20, 0x10, 0x30, 0x08
};


static void init(struct fmt_main *fmt_main)
{
	DES_std_init(); // Used DES_std.c to perform des_crypt() on CPU
	device_format_init(fmt_main, &bitstream, options.acc_devices,
		options.verbosity);
}


// got valid(), split() from DES_std.c
// TODO: create some DES_common.c
static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *pos;

	if (!ciphertext[0] || !ciphertext[1]) return 0;

	for (pos = &ciphertext[2]; atoi64[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos && *pos != ',') return 0;

	if (atoi64[ARCH_INDEX(*(pos - 1))] & 3) return 0;

	switch (pos - ciphertext) {
	case CIPHERTEXT_LENGTH_1:
		return 1;

	case CIPHERTEXT_LENGTH_2:
		if (atoi64[ARCH_INDEX(ciphertext[12])] & 3) return 0;
		return 2;

	default:
		return 0;
	}
}


static char *split(char *ciphertext, int index, struct fmt_main *pFmt)
{
	static char out[14];

	if (index) {
		memcpy(out, &ciphertext[2], 2);
		memcpy(&out[2], &ciphertext[13], 11);
	} else
		memcpy(out, ciphertext, 13);
	out[13] = 0;

/* Replace potential invalid salts with their valid counterparts */
	unsigned int salt = DES_raw_get_salt(out);
	out[0] = itoa64[salt & 0x3f];
	out[1] = itoa64[salt >> 6];

	return out;
}


// Full "binary": used by cmp_exact()
// Originally based on DES_raw_get_binary(), uses
// bitswapped table that eliminates inner loop
static uint64_t get_binary_full(char *ciphertext)
{
	uint64_t binary;
	int ofs, chr, c, dst_idx;

	if (ciphertext[13]) ofs = 9; else ofs = 2;

	binary = 0;
	dst_idx = 0;
	for (chr = 0; chr < 11; chr++) {
		c = DES_atoi64_bitswapped[ARCH_INDEX(ciphertext[chr + ofs])];
		binary |= (uint64_t)c << dst_idx;
		dst_idx += 6;
	}

	return binary;
}


// Partial "binary":
// - stored in db_password
// - sent to device
// - used as argument to cmp_one()
static unsigned char *get_binary(char *ciphertext)
{
	static unsigned char out[5];

	uint64_t binary = get_binary_full(ciphertext);
	out[0] = binary;
	out[1] = binary >> 8;
	out[2] = binary >> 16;
	out[3] = binary >> 24;
	out[4] = (binary >> 32) & BINARY_LAST_BYTE_MASK;

	return out;
}


static void *salt(char *ciphertext)
{
	static unsigned char out[2];

	int salt = DES_raw_get_salt(ciphertext);
	out[0] = salt;
	out[1] = salt >> 8;

	return out;
}


// *****************************************************************
//
// Perform des_crypt() and comparison on CPU.
//
// * Used functions from DES_std.c
// * Binaries produced by DES_std_crypt() and DES_std_get_binary()
//   are different from those stored in the database and sent to devices.
//
// *****************************************************************
#define DES_32_TO_16(x) \
	(((((x) & (0xF << 1)) >> 1)) | \
	((((x) & (0xF0 << 5)) >> 5)) | \
	((((x) & (0xF00 << 9)) >> 9)) | \
	((((x) & (0xF000 << 13)) >> 13)))

// TODO: move to some DES_common.c
#define DES_24_TO_32(x) \
	(((x) & 077) | \
	(((x) & 07700) << 2) | \
	(((x) & 0770000) << 4) | \
	(((x) & 077000000) << 6))

#if DES_128K
#define DES_UNDO_SIZE_FIX(x) \
	((((x) >> 1) & 0xFF00FF00) | (((x) & 0x00FF00FF) >> 3))
#else
#define DES_UNDO_SIZE_FIX(x) \
	((x) >> DES_SIZE_FIX)
#endif


unsigned int DES_salt_raw_to_std(void *salt_in)
{
	unsigned int salt;
	salt = *(unsigned char *)salt_in | *((unsigned char *)salt_in + 1) << 8;
	salt = DES_24_TO_32(salt);
	return (ARCH_WORD)DES_DO_SIZE_FIX(salt);
}


uint64_t DES_binary_std_to_raw(DES_binary binary, unsigned int salt)
{
	uint64_t result;
	ARCH_WORD mask;
	ARCH_WORD b[4];
	ARCH_WORD raw[2];
	ARCH_WORD *out;

	b[0] = binary[0];
#if ARCH_BITS >= 64
	b[1] = binary[0] >> 32;
	b[2] = binary[1];
	b[3] = binary[1] >> 32;
#else
	b[1] = binary[1];
	b[2] = binary[2];
	b[3] = binary[3];
#endif

	mask = (b[0] ^ b[1]) & salt;
	b[0] ^= mask;
	b[1] ^= mask;

	mask = (b[2] ^ b[3]) & salt;
	b[2] ^= mask;
	b[3] ^= mask;

	b[0] = DES_UNDO_SIZE_FIX(b[0]);
	b[1] = DES_UNDO_SIZE_FIX(b[1]);
	b[2] = DES_UNDO_SIZE_FIX(b[2]);
	b[3] = DES_UNDO_SIZE_FIX(b[3]);

	raw[0] = DES_32_TO_16(b[0]) | (DES_32_TO_16(b[1]) << 16);
	raw[1] = DES_32_TO_16(b[2]) | (DES_32_TO_16(b[3]) << 16);

	out = DES_do_FP(raw);

	result = (unsigned)(out[0]);
	result |= (uint64_t)(out[1]) << 32;
	return result;
}


static uint64_t des_crypt(void *salt, char *key)
{
	uint64_t result;
	unsigned int salt_std;
	DES_binary binary;

	salt_std = DES_salt_raw_to_std(salt);
	DES_std_set_salt(salt_std);

	DES_std_set_key(key);
	DES_std_crypt(DES_KS_current, binary);

	result = DES_binary_std_to_raw(binary, salt_std);
	//fprintf(stderr,"DES_binary_std_to_raw(%s): %016llx\n",key,result);
	return result;
}


extern struct task_list *task_list;


static void task_result_des_crypt(struct task_result *result)
{
	result->binary = mem_alloc(8);

	*(uint64_t *)result->binary
			= des_crypt(cmp_config.salt_ptr, result->key);
}


static int crypt_all(int *pcount, struct db_salt *salt)
{
	int result_count;

	cmp_config_new(salt, salt->salt, 2);

	result_count = device_format_crypt_all(pcount, salt);
	if (result_count)
		task_result_execute(task_list, task_result_des_crypt);

	return result_count;
}


static int cmp_one(void *binary, int index)
{
	struct task_result *result = task_result_by_index(task_list, index);
	//fprintf(stderr,"cmp_one(%d) %s\n",index, result->key);
	if (!result || !result->binary) {
		fprintf(stderr,"cmp_one(%d): no task_result or binary\n", index);
		error();
	}
	if (memcmp(result->binary, binary, 4))
		return 0;

	return (((unsigned char *)result->binary)[4] & BINARY_LAST_BYTE_MASK)
			== ((unsigned char *)binary)[4];
}


static int cmp_exact(char *source, int index)
{
	struct task_result *result = task_result_by_index(task_list, index);

	return *(uint64_t *)result->binary == get_binary_full(source);
}


struct fmt_main fmt_ztex_descrypt = {
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
		1, //MIN_KEYS_PER_CRYPT,
		1, //MAX_KEYS_PER_CRYPT,
		//FMT_DEVICE_CMP |
		FMT_CASE | FMT_TRUNC | FMT_MASK, // | FMT_REMOVE,
		{ NULL },
		{ NULL },
		tests
	}, {
		init, //device_format_init,
		device_format_done,
		device_format_reset,
		fmt_default_prepare,
		valid,
		split,
		(void *(*)(char *)) get_binary,
		salt,
		{ NULL }, // tunable costs
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
		crypt_all, //device_format_crypt_all,
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
		cmp_one, //device_format_cmp_one,
		cmp_exact //device_format_cmp_exact
	}
};

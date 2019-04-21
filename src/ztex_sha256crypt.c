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

#include "ztex/device_bitstream.h"
#include "ztex/device_format.h"
#include "ztex/task.h"
#include "ztex/pkt_comm/cmp_config.h"


#define FORMAT_LABEL		"sha256crypt-ztex"
#define ALGORITHM_NAME		"sha256crypt ZTEX"

#define FORMAT_NAME		"crypt(3) $5$"
#define FORMAT_TAG			"$5$"
#define FORMAT_TAG_LEN		(sizeof(FORMAT_TAG)-1)

#define BENCHMARK_COMMENT	" (rounds=5000)"
#define BENCHMARK_LENGTH	0x107

#define CIPHERTEXT_LENGTH		43

// Data structures differ from ones from CPU implementation:
// - Only partial hash in the database (BINARY_SIZE=4)
// - The hardware allows candidate length no more than 32
//
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE			4
#define BINARY_ALIGN		4
#define SALT_SIZE			sizeof(sha256crypt_salt_t)
#define SALT_ALIGN			4

#define ROUNDS_PREFIX          "rounds="
#define ROUNDS_DEFAULT         5000
#define ROUNDS_MIN             1
#define ROUNDS_MAX             999999999

#define	SALT_LENGTH			16

// unable to use sha256crypt_common.h
//#include "sha256crypt_common.h"


static struct device_bitstream bitstream = {
	// bitstream ID (check is performed by querying operating bitstream)
	0x256c,
	"$JOHN/ztex/ztex115y_sha256crypt.bit",
	// parameters for high-speed packet communication (pkt_comm)
	{ 2, 7422, 4094 },
	// computing performance estimation (in candidates per interval)
	// (keys * mask_num_cand)/crypt_all_interval per jtr_device.
	1,			// set by init() base on john.conf setting
	4096,		// keys/fpga for self-test
	565248,		// Would be ~20 MB of USB traffic on 32-byte keys
	512,		// Max. number of entries in onboard comparator.
	23 * 12,	// Min. keys for effective device utilization
	0,
	1, { 175 },	// Programmable clocks
	"sha256crypt",	// label for configuration file
	NULL, 0		// Initialization data
};


static struct fmt_tests tests[] = {
	// from CPU/GPU implementations
	{"$5$LKO/Ute40T3FNF95$U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9",
		"U*U*U*U*"},
	{"$5$LKO/Ute40T3FNF95$fdgfoJEBoMajNxCv3Ru9LyQ0xZgv0OBMQoq80LQ/Qd.",
		"U*U***U"},
	{"$5$LKO/Ute40T3FNF95$8Ry82xGnnPI/6HtFYnvPBTYgOL23sdMXn8C29aO.x/A",
		"U*U***U*"},
	{"$5$XSLWLBSQUCNOWXOB$i7Ho5wUAIjsH2e2zA.WarqYLWir5nmZbUEcjK//Or7.",
		"hgnirgayjnhvi"},
	{"$5$VDCTRFOIDQXRQVHR$uolqT0wEwU.pvI9jq5xU457JQpiwTTKX3PB/9RS4/h4",
		"o"},
	{"$5$EKt.VLXiPjwyv.xe$52wdOp9ixFXMsHDI1JcCw8KJ83IakDP6J7MIEV2OUk0",
		"1234567"},

	// salt_len < 16
	{"$5$rounds=5019$0.2345.789.bede$MkvvIivtYEIOJcDzMEvma3ParB"
		"1/s9Ht02poIWA1RK7", "salt15,key=13"},
	{"$5$rounds=5023$bQEwn2FVUb6ATd$qVlYFRnSpOg64SPaVY/1CBTrbCY"
		"5Kv6Y.Km/Um7jg61", "test #2: salt_len=14,key_len=31"},
	{"$5$TGf3jSp.tVaZB$WD6RH0Gzk5pb5Vt1Zq8e0hUWoRu3aq5iDPMl9kXdZRA",
		"s13_k6"},
	{"$5$CX9jFAaMBveU$vJ93dP0f1AMlr6nOMqQn9.yq9/3Px6QK44XpFXln9I/",
		"salt=12"},
	{"$5$rounds=4995$gjBVWL7tGHdK$Iwj/2BP.b1rrg6/B.fC4HIDhmhLZB"
		"uw8SrCeAXoSpH5", "salt11_key12"},
	{"$5$XDlt.8rtP$pO.M.p576fEXYR/d6sUlmU1SQm0/r8V1jDBAswp.5n2",
		"salt9:key_len=16"},
	{"$5$rounds=4999$bbeWqaag$VcKES/HMbDs9yDiJC2vyS4RuPN83cfkgdMfx"
		"8V5KdJB", "salt=8"},
	{"$5$rounds=5022$bQ7rLwn$aUIOwEgSRRrpGlLV5Jt5DtRNzSmyv54dMn"
		"uCCaD7CtC", "salt7key9"},
	{"$5$GH0itE$i1kIs5UMcM.Qomz3.2L2INxGYlaKRBDArZ6TNmh9ed7",
		"salt=6key=12"},
	{"$5$HfD3B$bVW9AObAFBZZ7KopQxRwaTs.X2/aVrYt55mW6f6EXl7",
		"s5k4"},
	{"$5$=$Qh125aRhMbwg8Phe/jIjQwos/v9I.vR/e7R1rjiYfBC",
		"salt1,key11"},

	// from the reference implementation
	{"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
		"Hello world!"},
/*
	// slows down --test
	{"$5$rounds=65535$szayT5KLiH2WRs11$VNArvxOyEfO/EQzr0tWkuwuL"
		"0ZD5frqQ7andlvqZDc3", "test64Krounds-1"},
	{"$5$rounds=65536$4GFbG5JAjHhgLKnt$5N5qlIa.QZinNR5mZTaJvntL"
		"g0JMVOvPJG3egctbV96", "test64Krounds-2"},
	{"$5$rounds=65537$8yfgGFDBht5hbfsf$SmnBXB9a7bfdYej74QtAEgaG"
		"GEpv7YQx9RP09O/xvQ8", "test64Krounds-3"},
	{"$5$rounds=1024000$fg80uTCVDKPeTbnB$N8bF/pNbfCoI1ImDdG8rKV"
		"OBvrbHzXtElv0QivEyvi4", "heavier_thing"},
	// times out in 5s (increase the default)
	{"$5$rounds=4096000$AFhfg9h8z.GEwvcB$tNR5A1CALj4bsC41VTisok"
		"zcn9Cc26Tr.oi2dJ.ZLl2", "device_format.c:TASK_TIMEOUT"},
*/
	{"$5$rounds=4972$0/2345.789//edef$DDPKQRM7xJkpe4pdf13My8qCJ"
		"PeFmXn6nNiwYk.R.wB", "abc"},
	{"$5$rounds=4970$0.234.6789.bc/ef$7NDazjArUHJs988r5ovAyd5tI"
		"kJybwD9JOibJfzgWuD", "12345678"},
	{"$5$012/45.7/9ab/def$wz2Bni8S/YVASQHPTNWPiUd17QwYow5qLbmSUvgZhd1",
		"test #3: salt_len=16, key_len=32"},
	{"$5$RFGhdnBMk0PYdQAN$GMIdTVp3gVpcOP2G4F7d74Vp3RbjSv7Z1aWA7kBkYiC",
		"salt_len=16,key_len=23."},
	{"$5$R.BGHLcxaqOIU1Fd$v56KjRPkbT6HoXm4G.YVYXGBH.D7alOUbsS2ybx8or2",
		"8-bit-chars\195\195\195"},
	{NULL}
};


typedef struct {
	unsigned int len;
	unsigned int rounds;
	unsigned char salt[16];
} sha256crypt_salt_t;


static int valid(char * ciphertext, struct fmt_main * self) {
	char *pos, *start;
	char *salt_pos, *salt_end_pos;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
			return 0;

	ciphertext += FORMAT_TAG_LEN;

	if (!strncmp(ciphertext, ROUNDS_PREFIX,
			sizeof(ROUNDS_PREFIX) - 1)) {
		const char *num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
		char *endp;
		if (!strtoul(num, &endp, 10))
					return 0;
		if (*endp == '$')
			ciphertext = endp + 1;
	}
	salt_pos = ciphertext;
	for (pos = ciphertext; *pos && *pos != '$'; pos++);
	if (!*pos || pos > &ciphertext[SALT_LENGTH])
		return 0;
	salt_end_pos = pos;

	start = ++pos;
	while (atoi64[ARCH_INDEX(*pos)] != 0x7F) pos++;
	if (*pos || pos - start != CIPHERTEXT_LENGTH) return 0;
	if (salt_end_pos == salt_pos) {
		printf("Warning: ZTEX: sha256crypt hash with salt_length=0 skipped.\n");
		return 0;
	}
	return 1;
}


/* ------- To binary functions ------- */
#define TO_BINARY(b1, b2, b3) \
	value = (uint32_t)atoi64[ARCH_INDEX(pos[0])] | \
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[2])] << 12) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[3])] << 18); \
	pos += 4; \
	out[b1] = value >> 16; \
	out[b2] = value >> 8; \
	out[b3] = value;

static void * get_binary(char * ciphertext) {
	static uint32_t outbuf[32/4];
	uint32_t value;
	char *pos = strrchr(ciphertext, '$') + 1;
	unsigned char *out = (unsigned char*)outbuf;
	int i=0;

	do {
		TO_BINARY(i, (i+10)%30, (i+20)%30);
		i = (i+21)%30;
	} while (i != 0);
	value = (uint32_t)atoi64[ARCH_INDEX(pos[0])] |
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6) |
		((uint32_t)atoi64[ARCH_INDEX(pos[2])] << 12);
	out[31] = value >> 8;
	out[30] = value;
	return (void *)out;
}


static void *get_salt(char *ciphertext)
{
	static sha256crypt_salt_t out;
	int len;

	memset(&out, 0, sizeof(out));
	out.rounds = ROUNDS_DEFAULT;
	ciphertext += FORMAT_TAG_LEN;
	if (!strncmp(ciphertext, ROUNDS_PREFIX,
	             sizeof(ROUNDS_PREFIX) - 1)) {
		const char *num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
		char *endp;
		unsigned long int srounds = strtoul(num, &endp, 10);
		if (*endp == '$')
		{
			ciphertext = endp + 1;
			srounds = srounds < ROUNDS_MIN ?
				ROUNDS_MIN : srounds;
			out.rounds = srounds > ROUNDS_MAX ?
				ROUNDS_MAX : srounds;
		}
	}

	for (len = 0; ciphertext[len] != '$'; len++);

	if (len > SALT_LENGTH)
		len = SALT_LENGTH;

	memcpy(out.salt, ciphertext, len);
	out.len = len;
	return &out;
}


static unsigned int iteration_count(void *salt)
{
	sha256crypt_salt_t *sha256crypt_salt;

	sha256crypt_salt = salt;
	return sha256crypt_salt->rounds;
}


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
	const int TARGET_ROUNDS_1KPC = 320*1024;

	target_rounds = cfg_get_int("ZTEX:", bitstream.label,
			"TargetRounds");
	if (target_rounds <= 0)
		target_rounds = 5000;

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
	static int warning_target_rounds = 0;
	int curr_rounds = salt->cost[0];

	int result;
	sha256crypt_salt_t *sha256crypt_salt = salt->salt;
	unsigned char salt_buf[18]; // salt to send to device

	if (!warning_target_rounds && !bench_or_test_running
			&& (curr_rounds >= target_rounds * 4
			|| curr_rounds <= target_rounds / 4)
	) {
		fprintf(stderr, "Warning: TargetRounds=%d, processing"
			" hash with rounds=%d, expecting suboptimal performance or"
			" timeout, consider to adjust TargetRounds in john.conf\n",
			target_rounds, curr_rounds);
		warning_target_rounds = 1;
	}

	// 1 byte unused, 1 byte salt_len, 16 bytes salt in network byte order
	salt_buf[0] = 0;
	salt_buf[1] = sha256crypt_salt->len;
	memcpy(salt_buf + 2, sha256crypt_salt->salt, 16);

	cmp_config_new(salt, salt_buf, 18);

	result = device_format_crypt_all(pcount, salt);
	return result;
}


extern struct task_list *task_list;

static int cmp_exact(char *source, int index)
{
	struct task_result *result = task_result_by_index(task_list, index);
/*
	fprintf(stderr,"cmp_exact index %d, key '%s'\n",index,result->key);
	int i;
	for (i=0; i < 32; i++)
		fprintf(stderr,"%02x ", result->binary[i]);
	fprintf(stderr,"\n");
	for (i=0; i < 32; i++)
		fprintf(stderr,"%02x ", (((char *)get_binary(source)) + i)[0] & 0xFF);
	fprintf(stderr,"\n");
*/
	return !memcmp(result->binary, get_binary(source), 32);
}


struct fmt_main fmt_ztex_sha256crypt = {
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

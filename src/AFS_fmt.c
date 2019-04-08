/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2012,2015,2017 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "DES_std.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"AFS"
#define FORMAT_NAME			"Kerberos AFS"
#define FORMAT_TAG			"$K4$"
#define FORMAT_TAG_LEN			(sizeof(FORMAT_TAG)-1)

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0x208

#define PLAINTEXT_LENGTH		63
#define CIPHERTEXT_LENGTH		20

static struct fmt_tests tests[] = {
	{"$K4$e35e9294ecef926d,0123", "U*U*U*U*"},
	{"$K4$64c7c2aedccd70d6,0123456789", "U*U***U*"},
	{"$K4$d9e985b36268f168,01234567", "U*U***U"},
	{"$K4$b9615786dfb53297,longcellname", "longpassword"},
	{"$K4$a8dc8aeaa2c48a97,", ""},
	{"$K4$dfda85c7619183a2,XXXXXXXX", "XXXXXXXX"},
	{"$K4$e3e59de6f1d5eaf4,cell", "password355"},
	{"$K4$b02cc24aefbc865b,", "thisisaverylongpassword"},
	{NULL}
};

#define ALGORITHM_NAME			DES_STD_ALGORITHM_NAME

#define BINARY_SIZE			(3 * ARCH_SIZE)
#define BINARY_ALIGN			ARCH_SIZE
#define SALT_SIZE			40
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		0x80
#define MAX_KEYS_PER_CRYPT		0x100

#define AFS_SALT			"#~..........."	/* An invalid salt */
#define AFS_long_key			"52912979"	/* "kerberos" >> 1 */
#define AFS_long_IV			"kerberos"	/* :-) */

/*
 * They're only using 8 characters of crypt(3) output, effectively reducing
 * the hash size to 48 bits... We are emulating this behavior with bitmasks.
 */
#define AFS_MASK_16			DES_DO_SIZE_FIX(0xFFF9FFF9)
#if ARCH_BITS >= 64
#define AFS_BINARY_MASK \
	(AFS_MASK_16 | ((unsigned ARCH_WORD)AFS_MASK_16 << 32))
#else
#define AFS_BINARY_MASK			AFS_MASK_16
#endif

#define TOTAL_BINARY_MASK		(DES_BINARY_MASK & AFS_BINARY_MASK)

#if ARCH_LITTLE_ENDIAN
#define AFS_swap(x, y) \
	(y) = (x);
#else
#define AFS_swap(x, y) \
{ \
	tmp = (x); \
	tmp = (tmp << 16) | (tmp >> 16); \
	(y) = ((tmp & 0x00FF00FF) << 8) | ((tmp >> 8) & 0x00FF00FF); \
}
#endif

static struct {
	union {
		double dummy;
		DES_binary binary;
	} aligned;
	int is_long;
	char key[PLAINTEXT_LENGTH + 1];
} buffer[MAX_KEYS_PER_CRYPT];

static char cell[SALT_SIZE + 8];
static int cell_length;

static ARCH_WORD AFS_salt_binary;
static union {
	double dummy;
	DES_KS data;
} AFS_long_KS;
static DES_binary AFS_long_IV_binary;

static void init(struct fmt_main *self)
{
	uint32_t block[2];
#if !ARCH_LITTLE_ENDIAN
	uint32_t tmp;
#endif

	DES_std_init();

	AFS_salt_binary = DES_std_get_salt(AFS_SALT);

	DES_raw_set_key(AFS_long_key);
	memcpy(AFS_long_KS.data, DES_KS_current, sizeof(DES_KS));

	memcpy(block, AFS_long_IV, 8);
#if !ARCH_LITTLE_ENDIAN
	AFS_swap(block[0], block[0]);
	AFS_swap(block[1], block[1]);
#endif
	DES_std_set_block(block[0], block[1]);
	memcpy(AFS_long_IV_binary, DES_IV, sizeof(DES_binary));
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos;
	int index, count;
	unsigned int value;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)) return 0;

	for (pos = &ciphertext[FORMAT_TAG_LEN]; atoi16l[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos != ',' || pos - ciphertext != CIPHERTEXT_LENGTH) return 0;

	for (index = 0; index < 16; index += 2) {
		value = atoi16[ARCH_INDEX(ciphertext[index + 4])] << 4;
		value |= atoi16[ARCH_INDEX(ciphertext[index + 5])];

		count = 0;
		if (value)
		do {
			count++;
		} while ((value &= value - 1));

		if (!(count & 1)) return 0;
	}

	return 1;
}

static void *get_binary(char *ciphertext)
{
	static ARCH_WORD out[6];
	char base64[14];
	int known_long;
	int index;
	unsigned int value;

	out[0] = out[1] = 0;
	strcpy(base64, AFS_SALT);
	known_long = 0;
	ciphertext += FORMAT_TAG_LEN;

	for (index = 0; index < 16; index += 2) {
		value = atoi16[ARCH_INDEX(ciphertext[index])] << 4;
		value |= atoi16[ARCH_INDEX(ciphertext[index+1])];

		out[index >> 3] |= (value | 1) << ((index << 2) & 0x18);

		if (atoi64[value >>= 1] == 0x7F)
			known_long = 1;
		else
			base64[(index >> 1) + 2] = value;
	}

	if (known_long)
		out[2] = ~(ARCH_WORD)0;
	else
		memcpy(&out[2], DES_std_get_binary(base64), 16);

	return out;
}

static void *salt(char *ciphertext)
{
	static char out[SALT_SIZE + 1];

	strncpy(out, &ciphertext[21], SALT_SIZE);
	out[SALT_SIZE] = 0;

	return strlwr(out);
}

static int binary_hash_0(void *binary)
{
	if (((ARCH_WORD *)binary)[2] == ~(ARCH_WORD)0)
		return *(ARCH_WORD *)binary & PH_MASK_0;

	return DES_STD_HASH_0(((ARCH_WORD *)binary)[2]);
}

static int binary_hash_1(void *binary)
{
	if (((ARCH_WORD *)binary)[2] == ~(ARCH_WORD)0)
		return *(ARCH_WORD *)binary & PH_MASK_1;

	return DES_STD_HASH_1(((ARCH_WORD *)binary)[2]);
}

static ARCH_WORD to_short_hash(int index)
{
	char base64[14];
	char *ptr;
	int pos, value;

	strcpy(base64, AFS_SALT);
	ptr = &base64[2];

	for (pos = 0; pos < 8; pos++) {
		value = buffer[index].aligned.binary[pos >> 2];
		value >>= ((pos & 3) << 3) + 1;
		value &= 0x7F;

		if (atoi64[value] == 0x7F) return ~(ARCH_WORD)0;
		*ptr++ = value;
	}

	return *DES_std_get_binary(base64);
}

static int get_hash_0(int index)
{
	ARCH_WORD binary;

	if (buffer[index].is_long) {
		if ((binary = to_short_hash(index)) == ~(ARCH_WORD)0)
			return buffer[index].aligned.binary[0] & PH_MASK_0;
	} else
		binary = buffer[index].aligned.binary[0] & AFS_BINARY_MASK;
	return DES_STD_HASH_0(binary);
}

static int get_hash_1(int index)
{
	ARCH_WORD binary;

	if (buffer[index].is_long) {
		if ((binary = to_short_hash(index)) == ~(ARCH_WORD)0)
			return buffer[index].aligned.binary[0] & PH_MASK_1;
	} else
		binary = buffer[index].aligned.binary[0] & AFS_BINARY_MASK;
	return DES_STD_HASH_1(binary);
}

static void set_salt(void *salt)
{
	strnzcpy(cell, salt, SALT_SIZE);
	memset(&cell[cell_length = strlen(cell)], 0, 8);
}

static void set_key(char *key, int index)
{
	strnzcpy(buffer[index].key, key, sizeof(buffer[0].key));
}

static char *get_key(int index)
{
	return buffer[index].key;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index, pos, length;
	char xor[8];
	uint32_t space[(PLAINTEXT_LENGTH + SALT_SIZE + 8) / 4 + 1];
	uint32_t *ptr;
	ARCH_WORD space_binary[(PLAINTEXT_LENGTH + SALT_SIZE + 8) / 2 + 1];
	ARCH_WORD *ptr_binary;
	unsigned ARCH_WORD block[2];
	union {
		double dummy;
		DES_binary data;
	} binary;
	uint32_t key[2];
#if !ARCH_LITTLE_ENDIAN
	uint32_t tmp;
#endif

	DES_std_set_salt(AFS_salt_binary);
	memset(DES_IV, 0, sizeof(DES_IV));
	DES_count = 25;

	for (index = 0; index < count; index++)
	if ((length = strlen(buffer[index].key)) > 8)
		buffer[index].is_long = length;
	else {
		buffer[index].is_long = 0;

		memcpy(xor, cell, 8);
		for (pos = 0; pos < 8 && buffer[index].key[pos]; pos++)
			xor[pos] ^= buffer[index].key[pos];

		for (pos = 0; pos < 8; pos++)
			if (!xor[pos]) xor[pos] = 'X';

		DES_std_set_key(xor);
		DES_std_crypt(DES_KS_current, buffer[index].aligned.binary);
	}

	DES_std_set_salt(0);
	DES_count = 1;

	for (index = 0; index < count; index++)
	if ((length = buffer[index].is_long)) {
		memcpy(space, buffer[index].key, length);
		memcpy((char *)space + length, cell, cell_length + 8);

		memcpy(binary.data, AFS_long_IV_binary, sizeof(binary.data));

		length += cell_length;
		ptr = space;
		ptr_binary = space_binary;
		do {
			AFS_swap(*ptr++, block[0]);
			AFS_swap(*ptr++, block[1]);
			DES_std_set_block(block[0], block[1]);

			*ptr_binary++ = DES_IV[0];
			DES_IV[0] ^= binary.data[0];
			*ptr_binary++ = DES_IV[1];
			DES_IV[1] ^= binary.data[1];
#if ARCH_BITS < 64
			*ptr_binary++ = DES_IV[2];
			DES_IV[2] ^= binary.data[2];
			*ptr_binary++ = DES_IV[3];
			DES_IV[3] ^= binary.data[3];
#endif

			DES_std_crypt(AFS_long_KS.data, binary.data);

			length -= 8;
		} while (length > 0);

		DES_std_get_block(binary.data, block);
		AFS_swap(block[0] >> 1, key[0]);
		AFS_swap(block[1] >> 1, key[1]);
		DES_raw_set_key((char *)key);

		length = buffer[index].is_long + cell_length;
		ptr_binary = space_binary;
		do {
			DES_IV[0] = binary.data[0] ^ *ptr_binary++;
			DES_IV[1] = binary.data[1] ^ *ptr_binary++;
#if ARCH_BITS < 64
			DES_IV[2] = binary.data[2] ^ *ptr_binary++;
			DES_IV[3] = binary.data[3] ^ *ptr_binary++;
#endif

			DES_std_crypt(DES_KS_current, binary.data);

			length -= 8;
		} while (length > 0);

		DES_std_get_block(binary.data, block);
		buffer[index].aligned.binary[0] = block[0] | 0x01010101;
		buffer[index].aligned.binary[1] = block[1] | 0x01010101;
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
	if (buffer[index].is_long) {
		if (*(unsigned ARCH_WORD *)binary ==
		    buffer[index].aligned.binary[0])
			return 1;
	} else {
		if (((unsigned ARCH_WORD *)binary)[2] ==
		    (buffer[index].aligned.binary[0] & TOTAL_BINARY_MASK))
			return 1;
	}

	return 0;
}

static int cmp_one(void *binary, int index)
{
	if (buffer[index].is_long)
		return *(unsigned ARCH_WORD *)binary ==
			buffer[index].aligned.binary[0];

	return ((unsigned ARCH_WORD *)binary)[2] ==
		(buffer[index].aligned.binary[0] & TOTAL_BINARY_MASK);
}

static int cmp_exact(char *source, int index)
{
	ARCH_WORD *binary;
	int word;

	binary = get_binary(source);

	if (buffer[index].is_long) {
		if ((unsigned ARCH_WORD)binary[0] !=
		    buffer[index].aligned.binary[0] ||
		    (unsigned ARCH_WORD)binary[1] !=
		    buffer[index].aligned.binary[1])
			return 0;
	} else {
		for (word = 0; word < 16 / DES_SIZE; word++)
		if ((unsigned ARCH_WORD)binary[word + 2] !=
		    (buffer[index].aligned.binary[word] & TOTAL_BINARY_MASK))
			return 0;
	}

	return 1;
}

struct fmt_main fmt_AFS = {
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
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		salt,
		{ NULL },
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

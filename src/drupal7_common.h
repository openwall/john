/*
 * Drupal 7 phpass variant using SHA-512 and hashes cut at 258 bits.
 *
 * This software is Copyright (c) 2012 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 * These are 8 byte salted hashes with a loop count that defines the number
 * of loops to compute. Drupal uses 258 bits of the hash, this is a multiple of
 * 6 but not 8. I presume this is for getting unpadded base64. Anyway we store
 * an extra byte but for now we will only compare 256 bits. I doubt that will
 * pose any problems. Actually I'm not quite sure the last bits end up correct
 * from the current version of get_binary().
 *
 * Moved common stuff from drupal7_fmt_plug.c into drupal7.h
 * - Denis Burykin, 2018
 */

#define FORMAT_NAME			"$S$"
#define FORMAT_TAG			"$S$"
#define FORMAT_TAG_LEN		(sizeof(FORMAT_TAG)-1)

#define BENCHMARK_COMMENT		" (x16385)"
#define BENCHMARK_LENGTH		0x107

#define CIPHERTEXT_LENGTH		55

// Actual salt size is 9 (SALT_SIZE + 1)
#define SALT_SIZE			8
#define SALT_ALIGN			4


static struct fmt_tests tests[] = {
	{"$S$CwkjgAKeSx2imSiN3SyBEg8e0sgE2QOx4a/VIfCHN0BZUNAWCr1X", "virtualabc"},
	{"$S$CFURCPa.k6FAEbJPgejaW4nijv7rYgGc4dUJtChQtV4KLJTPTC/u", "password"},
	{"$S$C6x2r.aW5Nkg7st6/u.IKWjTerHXscjPtu4spwhCVZlP89UKcbb/", "NEW_TEMP_PASSWORD"},
	{NULL}
};


static int valid(char *ciphertext, struct fmt_main *self)
{
	int i;
	unsigned count_log2;

	if (strnlen(ciphertext, CIPHERTEXT_LENGTH + 1) != CIPHERTEXT_LENGTH)
		return 0;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;
	for (i = FORMAT_TAG_LEN; i < CIPHERTEXT_LENGTH; ++i)
		if (atoi64[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;

	count_log2 = atoi64[ARCH_INDEX(ciphertext[3])];
	if (count_log2 < 7 || count_log2 > 31)
		return 0;

	return 1;
}


static void * get_binary(char *ciphertext)
{
	int i;
	unsigned sixbits;
	static union {
		//unsigned char u8[BINARY_SIZE + 1];
		// Warning: BINARY_SIZE=32 in CPU implementation,
		// 4 in ZTEX implementation (only partial hash in the db)
		unsigned char u8[33];
		uint32_t u32;
	} out;
	int bidx=0;
	char *pos;

	pos = &ciphertext[FORMAT_TAG_LEN + 1 + 8];
	for (i = 0; i < 10; ++i) {
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		out.u8[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		out.u8[bidx++] |= (sixbits<<6);
		sixbits >>= 2;
		out.u8[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		out.u8[bidx++] |= (sixbits<<4);
		sixbits >>= 4;
		out.u8[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		out.u8[bidx++] |= (sixbits<<2);
	}
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	out.u8[bidx] = sixbits;
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	out.u8[bidx++] |= (sixbits<<6);
	sixbits >>= 2;
	out.u8[bidx] = sixbits;
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	out.u8[bidx++] |= (sixbits<<4);
	return out.u8;
}


static void * get_salt(char *ciphertext)
{
	static union {
		unsigned char u8[SALT_SIZE + 1];
		uint32_t u32;
	} salt;
	// store off the 'real' 8 bytes of salt
	memcpy(salt.u8, &ciphertext[FORMAT_TAG_LEN+1], 8);
	// append the 1 byte of loop count information.
	salt.u8[8] = ciphertext[FORMAT_TAG_LEN];
	return salt.u8;
}


static int salt_hash(void *salt)
{
	return *((uint32_t *)salt) & (SALT_HASH_SIZE - 1);
}


static unsigned int iteration_count(void *salt)
{
	return (unsigned int) 1 << (atoi64[ARCH_INDEX(((char*)salt)[8])]);
}

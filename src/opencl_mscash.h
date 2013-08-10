/*
 * This software is Copyright (c) 2013 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * This is a direct port of mscash-cuda format by Lukas Odzioba
 * <lukas dot odzioba at gmail dot com>
 */
#ifndef _MSCASH_H
#define _MSCASH_H

#define	KEYS_PER_CRYPT		(1024 * 512)

#define BINARY_SIZE		16
#define PLAINTEXT_LENGTH	27
#define SALT_LENGTH		19
#define SALT_SIZE		sizeof(mscash_salt)

#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

#define MAX(x,y)		((x) > (y) ? (x) : (y))
#define MIN(x,y)		((x) < (y) ? (x) : (y))
#define SHOW(x)			(printf("%s = %08x\n",#x,(x)))
# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

#define INIT_A			0x67452301
#define INIT_B			0xefcdab89
#define INIT_C			0x98badcfe
#define INIT_D			0x10325476

#define SQRT_2			0x5a827999
#define SQRT_3			0x6ed9eba1

static const char mscash_prefix[] = "M$";

typedef struct {
	unsigned char length;
	unsigned char v[PLAINTEXT_LENGTH];
} mscash_password;

typedef struct {
	unsigned int v[8];
} mscash_hash;

typedef struct {
	unsigned char length;
	char salt[SALT_LENGTH+1];
} mscash_salt;

#endif

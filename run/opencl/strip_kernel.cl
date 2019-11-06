/*
 * This software is Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "pbkdf2_hmac_sha1_unsplit_kernel.cl"
#define AES_SRC_TYPE __constant
#include "opencl_aes.h"

typedef struct {
	pbkdf2_salt pbkdf2;
	uchar data[1024];
} strip_salt;

typedef struct {
	uint32_t cracked;
} strip_out;

#define SQLITE_MAX_PAGE_SIZE 65536

/* verify validity of page */
inline int verify_page(uchar *page)
{
	uint32_t pageSize;
	uint32_t usableSize;

	if (page[3] > 2)
		return 0;

	if (memcmp_pc(&page[5], "\100\040\040", 3))
		return 0;

	pageSize = (page[0] << 8) | (page[1] << 16);

	if (((pageSize - 1) & pageSize) != 0 ||
	    pageSize > SQLITE_MAX_PAGE_SIZE || pageSize <= 256)
		return 0;

	usableSize = pageSize - page[4];

	if (usableSize < 480)
		return 0;

	return 1;
}

__kernel void strip(__global const pbkdf2_password *inbuffer,
                    __global pbkdf2_hash *dk,
                    __constant strip_salt *salt,
                    __global strip_out *out)
{
	uint idx = get_global_id(0);
	uchar master[32];
	uchar output[16];
	uchar iv[16];
	const int page_sz = 1008; /* 1024 - strlen(SQLITE_FILE_HEADER) */
	const int reserve_sz = 16; /* for HMAC off case */
	const int size = page_sz - reserve_sz;
	AES_KEY akey;

	pbkdf2(inbuffer[idx].v, inbuffer[idx].length,
	       salt->pbkdf2.salt, salt->pbkdf2.length, salt->pbkdf2.iterations,
	       dk[idx].v, salt->pbkdf2.outlen, salt->pbkdf2.skip_bytes);

	memcpy_gp(master, dk[idx].v, 32);
	memcpy_cp(iv, salt->data + size + 16, 16);

	AES_set_decrypt_key(master, 256, &akey);
	/* The verify_page function looks at output[0..7] only. */
	AES_cbc_decrypt(salt->data + 16, output, 16, &akey, iv);

	out[idx].cracked = verify_page(output);
}

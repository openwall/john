/* keyring2john processes input GNOME Keyring files into a format suitable for
 * use with JtR.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include "stdint.h"
#include "memory.h"
#include "misc.h"

#define KEYRING_FILE_HEADER "GnomeKeyring\n\r\0\n"
#define KEYRING_FILE_HEADER_LEN 16

typedef unsigned char guchar;
typedef unsigned int guint;
typedef int gint;
static int count;

/* helper functions for byte order conversions, header values are stored
 * in big-endian byte order */
static uint32_t fget32_(FILE * fp)
{
	unsigned char buf[4];
	int count;
	uint32_t v;
	count = fread(buf, 4, 1, fp);
	assert(count == 1);

	v = buf[0] << 24;
	v |= buf[1] << 16;
	v |= buf[2] << 8;
	v |= buf[3];
	return v;
}

static void get_uint32(FILE * fp, int *next_offset, uint32_t * val)
{
	*val = fget32_(fp);
	*next_offset = *next_offset + 4;
}

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}

static int get_utf8_string(FILE * fp, int *next_offset)
{
	uint32_t len;
	unsigned char *buf;
	get_uint32(fp, next_offset, &len);

	buf = (unsigned char*)malloc(len);
	assert(buf);
	if (len == 0xffffffff) {
		goto ok;
	} else if (len >= 0x7fffffff) {
		// bad
		goto bad;
	}
	/* read len bytes */
	count = fread(buf, len, 1, fp);
	if (count != 1)
		goto bad;
	*next_offset = *next_offset + len;
	goto ok;

bad:
	free(buf);
	return 0;
ok:
	free(buf);
	return 1;
}

static void buffer_get_attributes(FILE * fp, int *next_offset)
{

	guint list_size;
	guint type;
	guint val;
	int i;
	int ret;

	get_uint32(fp, next_offset, &list_size);
	for (i = 0; i < list_size; i++) {
		ret = get_utf8_string(fp, next_offset);
		assert(ret == 1);

		get_uint32(fp, next_offset, &type);
		switch (type) {
		case 0:	/* A string */
			get_utf8_string(fp, next_offset);
			break;
		case 1:	/* A uint32 */
			get_uint32(fp, next_offset, &val);
			break;
		}
	}
}


static int read_hashed_item_info(FILE * fp, int *next_offset, uint32_t n_items)
{

	int i;
	uint32_t id;
	uint32_t type;

	for (i = 0; i < n_items; i++) {
		get_uint32(fp, next_offset, &id);
		get_uint32(fp, next_offset, &type);
		buffer_get_attributes(fp, next_offset);
	}
	return 1;
}

static void process_file(const char *fname)
{
	FILE *fp;
	unsigned char buf[1024];
	int i, offset;
	uint32_t flags;
	uint32_t lock_timeout;
	unsigned char major, minor, crypto, hash;
	uint32_t tmp;
	uint32_t num_items;
	uint32_t crypto_size;
	uint32_t hash_iterations;
	unsigned char salt[8];
	unsigned char *to_decrypt;

	if (!(fp = fopen(fname, "rb"))) {
		fprintf(stderr, "%s : %s\n", fname, strerror(errno));
		return;
	}
	count = fread(buf, KEYRING_FILE_HEADER_LEN, 1, fp);
	assert(count == 1);
	if (memcmp(buf, KEYRING_FILE_HEADER, KEYRING_FILE_HEADER_LEN) != 0) {
		fprintf(stderr, "%s : Not a GNOME Keyring file!\n", fname);
		return;
	}
	offset = KEYRING_FILE_HEADER_LEN;
	major = fgetc(fp);
	minor = fgetc(fp);
	crypto = fgetc(fp);
	hash = fgetc(fp);
	offset += 4;

	if (major != 0 || minor != 0 || crypto != 0 || hash != 0) {
		fprintf(stderr, "%s : Un-supported GNOME Keyring file!\n",
		    fname);
		return;
	}
	// Keyring name
	if (!get_utf8_string(fp, &offset))
		goto bail;
	// ctime
	count = fread(buf, 8, 1, fp);
	if (count != 1)
		goto bail;
	offset += 8;
	// mtime
	count = fread(buf, 8, 1, fp);
	if (count != 1)
		goto bail;
	offset += 8;
	// flags
	get_uint32(fp, &offset, &flags);
	// lock timeout
	get_uint32(fp, &offset, &lock_timeout);
	// hash_iterations
	get_uint32(fp, &offset, &hash_iterations);
	// salt
	count = fread(salt, 8, 1, fp);
	if (count != 1)
		goto bail;
	offset += 8;
	// reserved
	for (i = 0; i < 4; i++) {
		get_uint32(fp, &offset, &tmp);
	}
	// num_items
	get_uint32(fp, &offset, &num_items);
	if (!read_hashed_item_info(fp, &offset, num_items))
		goto bail;

	// crypto_size
	get_uint32(fp, &offset, &crypto_size);
	fprintf(stderr, "%s: crypto size: %u offset : %d\n", fname, crypto_size, offset);

	/* Make the crypted part is the right size */
	if (crypto_size % 16 != 0)
		goto bail;

	to_decrypt = (unsigned char *) mem_alloc(crypto_size);
	count = fread(to_decrypt, crypto_size, 1, fp);
	assert(count == 1);
	printf("%s:$keyring$", basename(fname));
	print_hex(salt, 8);
	printf("*%d*%d*%d*", hash_iterations, crypto_size, 0);
	print_hex(to_decrypt, crypto_size);
	printf("\n");
	if(to_decrypt)
		MEM_FREE(to_decrypt);
	return;

bail:
	fprintf(stderr, "%s: parsing failed, please report this on john-users if input was a valid keyring!\n", fname);
	return;

}

static int usage()
{
	fprintf(stderr, "Usage: keyring2john [GNOME Keyring file(s)]\n");
	return 1;
}

int keyring2john(int argc, char **argv)
{
	int i = 1;

	if (argc < 2)
		return usage();
	for (; i < argc; i++)
		process_file(argv[i]);

	return 0;
}

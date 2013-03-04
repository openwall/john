#if !defined (_MSC_VER) && !defined (__MINGW32__)
/* Modified by Dhiru Kholia for JtR in August, 2012
 *
 * dmg.c
 *
 * hashkill - a hash cracking tool
 * Copyright (C) 2010 Milen Rangelov <gat3way@gat3way.eu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#include <stdio.h>
#include <math.h>
#include <unistd.h>
#include <string.h>
#include <alloca.h>
#include <fcntl.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

#include "stdint.h"
#include "gladman_fileenc.h"
#include "filevault.h"

#define ntohll(x) (((uint64_t) ntohl((x) >> 32)) | (((uint64_t) ntohl((uint32_t) ((x) & 0xFFFFFFFF))) << 32))

static int chunk_size;
static int headerver;
static cencrypted_v1_header header;
static cencrypted_v2_pwheader header2;

static void header_byteorder_fix(cencrypted_v1_header * hdr)
{
	hdr->kdf_iteration_count = htonl(hdr->kdf_iteration_count);
	hdr->kdf_salt_len = htonl(hdr->kdf_salt_len);
	hdr->len_wrapped_aes_key = htonl(hdr->len_wrapped_aes_key);
	hdr->len_hmac_sha1_key = htonl(hdr->len_hmac_sha1_key);
	hdr->len_integrity_key = htonl(hdr->len_integrity_key);
}

static void header2_byteorder_fix(cencrypted_v2_pwheader * pwhdr)
{
	pwhdr->blocksize = ntohl(pwhdr->blocksize);
	pwhdr->datasize = ntohll(pwhdr->datasize);
	pwhdr->dataoffset = ntohll(pwhdr->dataoffset);
	pwhdr->kdf_algorithm = ntohl(pwhdr->kdf_algorithm);
	pwhdr->kdf_prng_algorithm = ntohl(pwhdr->kdf_prng_algorithm);
	pwhdr->kdf_iteration_count = ntohl(pwhdr->kdf_iteration_count);
	pwhdr->kdf_salt_len = ntohl(pwhdr->kdf_salt_len);
	pwhdr->blob_enc_iv_size = ntohl(pwhdr->blob_enc_iv_size);
	pwhdr->blob_enc_key_bits = ntohl(pwhdr->blob_enc_key_bits);
	pwhdr->blob_enc_algorithm = ntohl(pwhdr->blob_enc_algorithm);
	pwhdr->blob_enc_padding = ntohl(pwhdr->blob_enc_padding);
	pwhdr->blob_enc_mode = ntohl(pwhdr->blob_enc_mode);
	pwhdr->encrypted_keyblob_size = ntohl(pwhdr->encrypted_keyblob_size);
}

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}

static void hash_plugin_parse_hash(char *filename)
{
	int fd;
	char buf8[8];
	int64_t cno = 0;
	int64_t data_size = 0;
	int64_t count = 0;
	unsigned char *chunk1 = NULL;
	unsigned char chunk2[4096];


	headerver = 0;
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open file: %s\n", filename);
		return;
	}
	if (read(fd, buf8, 8) <= 0) {
		fprintf(stderr, "%s is not a DMG file!\n", filename);
		return;
	}
	if (strncmp(buf8, "encrcdsa", 8) == 0) {
		headerver = 2;
	}

	else {
		if (lseek(fd, -8, SEEK_END) < 0) {
			fprintf(stderr, "Unable to seek in %s\n", filename);
			return;
		}
		if (read(fd, buf8, 8) <= 0) {
			fprintf(stderr, "%s is not a DMG file!\n", filename);
			return;
		}
		if (strncmp(buf8, "cdsaencr", 8) == 0) {
			headerver = 1;
		}
	}
	if (headerver == 0) {
		fprintf(stderr, "%s is not an encrypted DMG file!\n", filename);
		return;
	}
	// fprintf(stderr, "Header version %d detected\n", headerver);
	if (headerver == 1) {
		char *name;

		if (lseek(fd, -sizeof(cencrypted_v1_header), SEEK_END) < 0) {
			fprintf(stderr, "Unable to seek in %s\n", filename);
			return;
		}
		if (read(fd, &header, sizeof(cencrypted_v1_header)) < 1) {
			fprintf(stderr, "%s is not a DMG file!\n", filename);
			return;
		}
		header_byteorder_fix(&header);

		if (!(name = basename(filename)))
		    name = filename;

		fprintf(stderr, "%s (DMG v%d) successfully parsed, iterations "
		        "count %u\n", name, headerver,
		        header.kdf_iteration_count);

		printf("%s:$dmg$%d*%d*", name, headerver, header.kdf_salt_len);
		print_hex(header.kdf_salt, header.kdf_salt_len);
		printf("*%d*", header.len_wrapped_aes_key);
		print_hex(header.wrapped_aes_key, header.len_wrapped_aes_key);
		printf("*%d*", header.len_hmac_sha1_key);
		print_hex(header.wrapped_hmac_sha1_key, header.len_hmac_sha1_key);
		printf("*%u::::%s\n", header.kdf_iteration_count, filename);
	}
	else {
		char *name;

		if (lseek(fd, 0, SEEK_SET) < 0) {
			fprintf(stderr, "Unable to seek in %s\n", filename);
			return;
		}
		if (read(fd, &header2, sizeof(cencrypted_v2_pwheader)) < 1) {
			fprintf(stderr, "%s is not a DMG file!\n", filename);
			return;
		}
		header2_byteorder_fix(&header2);

		chunk_size = header2.blocksize;
		if (lseek(fd, header2.dataoffset, SEEK_SET) < 0) {
			fprintf(stderr, "Unable to seek in %s\n", filename);
			return;
		}
		cno = ((header2.datasize + 4095ULL) / 4096) - 2;
		data_size = header2.datasize - cno * 4096ULL;
		if (data_size < 0) {
			fprintf(stderr, "%s is not a valid DMG file!\n", filename);
			return;
		}
		if (header2.kdf_salt_len > 32) {
			fprintf(stderr, "%s is not a valid DMG file, salt length is too long!\n", filename);
			return;
		}

		if (!(name = basename(filename)))
		    name = filename;

		fprintf(stderr, "%s (DMG v%d) successfully parsed, iterations "
		        "count %u\n", filename, headerver,
		        header2.kdf_iteration_count);

		/* read starting chunk(s) */
		chunk1 = (unsigned char *) malloc(data_size);
		if (lseek(fd, header2.dataoffset + cno * 4096LL, SEEK_SET) < 0) {
			fprintf(stderr, "Unable to seek in %s\n", filename);
			return;
		}
		count = read(fd, chunk1, data_size);
		if (count < 1 || count != data_size) {
			fprintf(stderr, "Unable to read required data from %s\n", filename);
			free(chunk1);
			return;
		}
		/* read last chunk */
		if (lseek(fd, header2.dataoffset, SEEK_SET) < 0) {
			fprintf(stderr, "Unable to seek in %s\n", filename);
			return;
		}
		count = read(fd, chunk2, 4096);
		if (count < 1 || count != 4096) {
			fprintf(stderr, "Unable to read required data from %s\n", filename);
			free(chunk1);
			return;
		}

		/* output hash */
		printf("%s:$dmg$%d*%d*", name, headerver, header2.kdf_salt_len);
		print_hex(header2.kdf_salt, header2.kdf_salt_len);
		printf("*32*");
		print_hex(header2.blob_enc_iv, 32);
		printf("*%d*", header2.encrypted_keyblob_size);
		print_hex(header2.encrypted_keyblob, header2.encrypted_keyblob_size);
		printf("*%d*%d*", (int)cno, (int)data_size);
		print_hex(chunk1, data_size);
		printf("*1*");
		print_hex(chunk2, 4096);
		printf("*%u::::%s\n", header2.kdf_iteration_count, filename);
		free(chunk1);
	}
	close(fd);
}

int dmg2john(int argc, char **argv)
{
	int i;

	if (argc < 2) {
		puts("Usage: dmg2john [DMG files]");
		return -1;
	}
	for (i = 1; i < argc; i++)
		hash_plugin_parse_hash(argv[i]);

	return 0;
}
#endif

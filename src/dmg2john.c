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
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

#include "stdint.h"
#include "gladman_fileenc.h"
#include "filevault.h"
#include "misc.h"
#include "memdbg.h"

#define ntohll(x) (((uint64_t) ntohl((x) >> 32)) | (((uint64_t) ntohl((uint32_t) ((x) & 0xFFFFFFFF))) << 32))

#define LARGE_ENOUGH 8192

static int chunk_size;
static int headerver;
static cencrypted_v1_header header;
static cencrypted_v2_header header2;
static cencrypted_v2_password_header v2_password_header;

static void header_byteorder_fix(cencrypted_v1_header * hdr)
{
	hdr->kdf_iteration_count = htonl(hdr->kdf_iteration_count);
	hdr->kdf_salt_len = htonl(hdr->kdf_salt_len);
	hdr->len_wrapped_aes_key = htonl(hdr->len_wrapped_aes_key);
	hdr->len_hmac_sha1_key = htonl(hdr->len_hmac_sha1_key);
	hdr->len_integrity_key = htonl(hdr->len_integrity_key);
}

static void header2_byteorder_fix(cencrypted_v2_header * header)
{
	header->version = ntohl(header->version);
	header->enc_iv_size = ntohl(header->enc_iv_size);
	header->encMode = ntohl(header->encMode);
	header->encAlg = ntohl(header->encAlg);
	header->keyBits = ntohl(header->keyBits);
	header->prngalg = ntohl(header->prngalg);
	header->prngkeysize = ntohl(header->prngkeysize);
	header->blocksize = ntohl(header->blocksize);
	header->datasize = ntohll(header->datasize);
	header->dataoffset = ntohll(header->dataoffset);
	header->keycount = ntohl(header->keycount);
}

static void v2_key_header_pointer_byteorder_fix(cencrypted_v2_key_header_pointer *key_header_pointer)
{
	key_header_pointer->header_type = ntohl(key_header_pointer->header_type);
	key_header_pointer->header_offset = ntohl(key_header_pointer->header_offset);
	key_header_pointer->header_size = ntohl(key_header_pointer->header_size);
}

static void v2_password_header_byteorder_fix(cencrypted_v2_password_header *password_header)
{
	password_header->algorithm = ntohl(password_header->algorithm);
	password_header->prngalgo = ntohl(password_header->prngalgo);
	password_header->itercount = ntohl(password_header->itercount);
	password_header->salt_size = ntohl(password_header->salt_size);
	password_header->iv_size = ntohl(password_header->iv_size);
	password_header->blob_enc_keybits = ntohl(password_header->blob_enc_keybits);
	password_header->blob_enc_algo = ntohl(password_header->blob_enc_algo);
	password_header->blob_enc_padding = ntohl(password_header->blob_enc_padding);
	password_header->blob_enc_mode = ntohl(password_header->blob_enc_mode);
	password_header->keyblobsize = ntohl(password_header->keyblobsize);
}

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}

static void hash_plugin_parse_hash(char *in_filepath)
{
	int fd;
	char buf8[8];
	uint32_t i = 0;
	int64_t cno = 0;
	int64_t data_size = 0;
	int64_t count = 0;
	unsigned char *chunk1 = NULL;
	unsigned char chunk2[4096];
	char filepath[LARGE_ENOUGH];
	char name[LARGE_ENOUGH];
	char *filename;
	int is_sparsebundle = 0;

	int filepath_length = strnzcpyn(filepath, in_filepath, LARGE_ENOUGH);

	strnzcpyn(name, in_filepath, LARGE_ENOUGH);
	if (!(filename = basename(name))) {
	    filename = filepath;
	}

	if(strstr(filepath, ".sparsebundle")) {
		// The filepath given indicates this is a sparsebundle
		// A sparsebundle is simply a directory with contents.
		// Let's check to see if that is the case.
		struct stat file_stat;
		char *token_path;
		if (stat(filepath, &file_stat) != 0) {
			fprintf(stderr, "Can't stat file: %s\n", filename);
			return;
		}

		// Determine if the filepath given is a directory.
		if (!(file_stat.st_mode & S_IFDIR)) {
			fprintf(stderr, "%s claims to be a sparsebundle but isn't a directory\n", filename);
			return;
		}

		// Let's look to see if the token file exists.
		fprintf(stderr, "filepath = %s path_length = %d\n", filepath, filepath_length);
		if (filepath_length + 6 + 1 >= LARGE_ENOUGH) {
			fprintf(stderr, "Can't create token path. Path too long.\n");
			return;
		}

		is_sparsebundle = 1;

		token_path = strnzcat(filepath, "/token", LARGE_ENOUGH);
		strnzcpyn(filepath, token_path, LARGE_ENOUGH);
		strnzcpyn(name, filepath, LARGE_ENOUGH);
		if (!(filename = basename(name))) {
		    filename = filepath;
		}

	}

	headerver = 0;
	fd = open(filepath, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open file: %s\n", filename);
		return;
	}

	if (read(fd, buf8, 8) <= 0) {
		fprintf(stderr, "%s is not a DMG file!\n", filename);
		close(fd);
		return;
	}

	if (strncmp(buf8, "encrcdsa", 8) == 0) {
		headerver = 2;
	} else {
		if (lseek(fd, -8, SEEK_END) < 0) {
			fprintf(stderr, "Unable to seek in %s\n", filename);
			close(fd);
			return;
		}
		if (read(fd, buf8, 8) <= 0) {
			fprintf(stderr, "%s is not a DMG file!\n", filename);
			close(fd);
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
		if (lseek(fd, -sizeof(cencrypted_v1_header), SEEK_END) < 0) {
			fprintf(stderr, "Unable to seek in %s\n", filename);
			return;
		}
		if (read(fd, &header, sizeof(cencrypted_v1_header)) < 1) {
			fprintf(stderr, "%s is not a DMG file!\n", filename);
			return;
		}
		header_byteorder_fix(&header);

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
	} else {
		cencrypted_v2_key_header_pointer header_pointer;
		int password_header_found = 0;

		if (lseek(fd, 0, SEEK_SET) < 0) {
			fprintf(stderr, "Unable to seek in %s\n", filename);
			return;
		}
		if (read(fd, &header2, sizeof(cencrypted_v2_header)) < 1) {
			fprintf(stderr, "%s is not a DMG file!\n", filename);
			return;
		}

		header2_byteorder_fix(&header2);

		chunk_size = header2.blocksize;
		// If this is a sparsebundle then there is no data to seek
		// to in this file so we skip over this particular check.
		if (!is_sparsebundle) {
			if (lseek(fd, header2.dataoffset, SEEK_SET) < 0) {
				fprintf(stderr, "Unable to seek in %s\n", filename);
				return;
			}
		}

		if(strstr(name, ".sparseimage") || is_sparsebundle) {
			// If this file is a sparseimage then we want one of the first chunks as the other chunks could be empty.
			cno = 1;
			data_size = 8192;
		} else {
			cno = ((header2.datasize + 4095ULL) / 4096) - 2;
			data_size = header2.datasize - cno * 4096ULL;
		}

		if (data_size < 0) {
			fprintf(stderr, "%s is not a valid DMG file!\n", filename);
			return;
		}

		for (i = 0; i < header2.keycount; i++) {

			// Seek to the start of the key header pointers offset by the current key which start immediately after the v2 header.
			if (lseek(fd, (sizeof(cencrypted_v2_header) + (sizeof(cencrypted_v2_key_header_pointer)*i)), SEEK_SET) < 0) {
				fprintf(stderr, "Unable to seek to header pointers in %s\n", filename);
				return;
			}

			// Read in the key header pointer
			count = read(fd, &header_pointer, sizeof(cencrypted_v2_key_header_pointer));
			if (count < 1 || count != sizeof(cencrypted_v2_key_header_pointer)) {
				fprintf(stderr, "Unable to read required data from %s\n", filename);
				return;
			}

			v2_key_header_pointer_byteorder_fix(&header_pointer);

			// We, currently, only care about the password key header. If it's not the password header type skip over it.
			if (header_pointer.header_type != 1) {
				continue;
			}

			// Seek to where the password key header is in the file.
			if (lseek(fd, header_pointer.header_offset, SEEK_SET) < 0) {
				fprintf(stderr, "Unable to seek to password header in %s\n", filename);
				return;
			}

			// Read in the password key header but avoid reading anything into the keyblob.
			count = read(fd, &v2_password_header, sizeof(cencrypted_v2_password_header) - sizeof(unsigned char *));
			if (count < 1 || count != (sizeof(cencrypted_v2_password_header) - sizeof(unsigned char *))) {
				fprintf(stderr, "Unable to read required data from %s\n", filename);
				return;
			}

			v2_password_header_byteorder_fix(&v2_password_header);

			// Allocate the keyblob memory
			v2_password_header.keyblob = malloc(v2_password_header.keyblobsize);

			// Seek to the keyblob in the header
			if (lseek(fd, header_pointer.header_offset + sizeof(cencrypted_v2_password_header) - sizeof(unsigned char *), SEEK_SET) < 0) {
				fprintf(stderr, "Unable to seek to password header in %s\n", filename);
				free(v2_password_header.keyblob);
				return;
			}

			// Read in the keyblob
			count = read(fd, v2_password_header.keyblob, v2_password_header.keyblobsize);
			if (count < 1 || count != (v2_password_header.keyblobsize)) {
				fprintf(stderr, "Unable to read required data from %s\n", filename);
				free(v2_password_header.keyblob);
				return;
			}

			password_header_found = 1;

			// We only need one password header. Don't search any longer.
			break;
		}

		if (!password_header_found) {
			fprintf(stderr, "Password header not found in %s\n", filename);
			free(v2_password_header.keyblob);
			return;
		}

		if (v2_password_header.salt_size > 32) {
			fprintf(stderr, "%s is not a valid DMG file, salt length is too long!\n", filename);
			free(v2_password_header.keyblob);
			return;
		}

		fprintf(stderr, "%s (DMG v%d) successfully parsed, iterations "
		        "count %u\n", name, headerver,
		        v2_password_header.itercount);

		if (is_sparsebundle) {
			// If this is a sparsebundle then we need to get the chunks
			// of data out of 0 from the bands directory. Close the
			// previous file and open bands/0
			char *bands_path;
			if (close(fd) != 0) {
				fprintf(stderr, "Failed closing file %s\n", filename);
				free(v2_password_header.keyblob);
				return;
			}

			filepath_length = strnzcpyn(filepath, in_filepath, LARGE_ENOUGH);

			strnzcpyn(name, in_filepath, LARGE_ENOUGH);

			// See if we have enough room to append 'bands/0' to the path.
			if (filepath_length + 8 + 1 >= LARGE_ENOUGH) {
				fprintf(stderr, "Can't create bands path. Path too long.\n");
				free(v2_password_header.keyblob);
				return;
			}

			bands_path = strnzcat(filepath, "/bands/0", LARGE_ENOUGH);
			strnzcpyn(filepath, bands_path, LARGE_ENOUGH);
			strnzcpyn(name, filepath, LARGE_ENOUGH);
			if (!(filename = basename(name))) {
			    filename = filepath;
			}

			// Open the file for reading.
			fd = open(filepath, O_RDONLY);
			if (fd < 0) {
				fprintf(stderr, "Can't open file: %s\n", filename);
				return;
			}

			// Since we are in a different file the we can ignore the dataoffset
			header2.dataoffset = 0;
		}

		/* read starting chunk(s) */
		chunk1 = (unsigned char *) malloc(data_size);
		if (lseek(fd, header2.dataoffset + cno * 4096LL, SEEK_SET) < 0) {
			fprintf(stderr, "Unable to seek in %s\n", filename);
			free(chunk1);
			free(v2_password_header.keyblob);
			return;
		}
		count = read(fd, chunk1, data_size);
		if (count < 1 || count != data_size) {
			fprintf(stderr, "Unable to read required data from %s\n", filename);
			free(chunk1);
			free(v2_password_header.keyblob);
			return;
		}
		/* read last chunk */
		if (lseek(fd, header2.dataoffset, SEEK_SET) < 0) {
			fprintf(stderr, "Unable to seek in %s\n", filename);
			free(chunk1);
			free(v2_password_header.keyblob);
			return;
		}
		count = read(fd, chunk2, 4096);
		if (count < 1 || count != 4096) {
			fprintf(stderr, "Unable to read required data from %s\n", filename);
			free(chunk1);
			free(v2_password_header.keyblob);
			return;
		}

		/* output hash */
		printf("%s:$dmg$%d*%d*", name, headerver, v2_password_header.salt_size);
		print_hex(v2_password_header.salt, v2_password_header.salt_size);
		printf("*32*");
		print_hex(v2_password_header.iv, 32);
		printf("*%d*", v2_password_header.keyblobsize);
		print_hex(v2_password_header.keyblob, v2_password_header.keyblobsize);
		printf("*%d*%d*", (int)cno, (int)data_size);
		print_hex(chunk1, data_size);
		printf("*1*");
		print_hex(chunk2, 4096);
		printf("*%u::::%s\n", v2_password_header.itercount, filename);

		free(chunk1);
		free(v2_password_header.keyblob);
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

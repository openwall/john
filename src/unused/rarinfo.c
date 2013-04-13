#include <stdio.h>
#include <stdlib.h>
#include "stdint.h"
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "misc.h"
#include "common.h"
#include "arch.h"
#include "params.h"
#include "crc32.h"

static void process_file(const char *filename)
{
	FILE *fp;
	unsigned char marker_block[7];
	unsigned char archive_header_block[13];
	unsigned char file_header_block[40];
	int i, count, type;

	if (!(fp = fopen(filename, "rb"))) {
		fprintf(stderr, "! %s : %s\n", filename, strerror(errno));
		return;
	}
	/* marker block */
	memset(marker_block, 0, 7);
	count = fread(marker_block, 1, 7, fp);
	if (memcmp(marker_block, "\x52\x61\x72\x21\x1a\x07\x00", 7)) {
		fprintf(stderr, "! %s : Not a RAR file\n", filename);
		fclose(fp);
		return;
	}
	/* archive header block */
	count = fread(archive_header_block, 1, 13, fp);
	assert(count == 13);
	assert(archive_header_block[2] == 0x73);
	/* find encryption mode used (called type in output line format) */
	uint16_t archive_header_head_flags =
	    archive_header_block[4] << 8 | archive_header_block[3];
	if (archive_header_head_flags & 0x0080) {	/* file header block is encrypted */
		type = 0;	/* RAR file was created using -hp flag */
	} else
		type = 1;
	/* file header block */
	count = fread(file_header_block, 1, 32, fp);
	assert(count == 32);
	if (type == 1)
		assert(file_header_block[2] == 0x74);
	uint16_t file_header_head_flags =
	    file_header_block[4] << 8 | file_header_block[3];
	/* if type = 1, check if encryption is being used? */
	int is_encrypted;
	if (type == 1 && !(file_header_head_flags & 0x04)) {
		fprintf(stderr, "! %s : RAR file is not encrypted\n",
		    filename);
		is_encrypted = 0;

	}

	/* process -hp mode files */
	if (type == 0) {	/* use Marc's end-of-archive block decrypt trick */
		printf("%s:$rar3$*%d*", filename, type);
		fseek(fp, -24, SEEK_END);
		unsigned char buf[24];
		count = fread(buf, 1, 24, fp);
		for (i = 0; i < 8; i++) {
			printf("%c%c", itoa16[ARCH_INDEX(buf[i] >> 4)],
			    itoa16[ARCH_INDEX(buf[i] & 0x0f)]);
		}
		printf("*");
		for (i = 8; i < 24; i++) {
			printf("%c%c", itoa16[ARCH_INDEX(buf[i] >> 4)],
			    itoa16[ARCH_INDEX(buf[i] & 0x0f)]);
		}
		printf("\n");
	} else {    /* TODO: process -p mode files */
		if (!(file_header_head_flags & 0x8000)) {
			fprintf(stderr, "bailing out ...\n");
		}
		uint16_t file_header_head_size =
		    file_header_block[6] << 8 | file_header_block[5];
		int file_header_pack_size;
		memcpy(&file_header_pack_size, file_header_block + 7, 4);
		int file_header_unp_size;
		memcpy(&file_header_unp_size, file_header_block + 11, 4);
		fprintf(stderr, "HEAD_SIZE : %d, PACK_SIZE : %d, UNP_SIZE : %d\n",
		    file_header_head_size, file_header_pack_size,
		    file_header_unp_size);

		/* calculate EXT_TIME size */
		int EXT_TIME_SIZE = file_header_head_size - 32;

		unsigned char rejbuf[32];
		if (file_header_head_flags & 0x100) {
			fprintf(stderr, "! HIGH_PACK_SIZE present\n");
			fread(rejbuf, 1, 4, fp);
			EXT_TIME_SIZE -= 4;
		}
		if (file_header_head_flags & 0x100) {
			fprintf(stderr, "! HIGH_UNP_SIZE present\n");
			fread(rejbuf, 1, 4, fp);
			EXT_TIME_SIZE -= 4;
		}
		/* file name processing */
		uint16_t file_name_size =
		    file_header_block[27] << 8 | file_header_block[26];
		fprintf(stderr, "file name size : %d bytes\n", file_name_size);
		unsigned char file_name[128];
		fread(file_name, 1, file_name_size, fp);
		file_name[file_name_size] = 0;
		fprintf(stderr, "file name : %s\n", file_name);
		EXT_TIME_SIZE -= file_name_size;
		/* SALT processing */
		unsigned char SALT[8];
		if (file_header_head_flags & 0x400) {
			EXT_TIME_SIZE -= 8;
			fread(SALT, 1, 8, fp);
		}
		/* EXT_TIME processing */
		if (file_header_head_flags & 0x1000) {
			fprintf(stderr, "! EXT_TIME present with size %d\n",
			    EXT_TIME_SIZE);
			fread(rejbuf, 1, EXT_TIME_SIZE, fp);
		}
		/* process encrypted data of size "file_header_pack_size" */
		if (file_header_head_flags & 0x400) {
    		printf("%s:$rar3$*%d*", filename, type);
	    	for (i = 0; i < 8; i++) { /* encode SALT */
		    	printf("%c%c", itoa16[ARCH_INDEX(SALT[i] >> 4)],
			        itoa16[ARCH_INDEX(SALT[i] & 0x0f)]);
    		}
        }
		printf("*");
		unsigned char FILE_CRC[4];
		memcpy(FILE_CRC, file_header_block + 16, 4);
		for (i = 0; i < 4; i++) { /* encode FILE_CRC */
			printf("%c%c", itoa16[ARCH_INDEX(FILE_CRC[i] >> 4)],
			    itoa16[ARCH_INDEX(FILE_CRC[i] & 0x0f)]);
		}
		/* fp is at compressed plaintext or ciphertext location */
		long pos = ftell(fp);
		printf("*%d*%d*%s*%ld\n",file_header_pack_size, file_header_unp_size, filename, pos);
		printf("dumping data at %ld\n", pos);
		fread(rejbuf, 1, 16, fp);
		for (i = 0; i < 16; i++) {
			printf("%x ", rejbuf[i]);
		}
		printf("\n");

	}
	fclose(fp);
}

int main(int argc, char **argv)
{
	int i;

	if (argc < 2) {
		printf("Usage: %s [rar files]", argv[0]);
		return 0;
	}
	for (i = 1; i < argc; i++)
		process_file(argv[i]);

	return 0;
}

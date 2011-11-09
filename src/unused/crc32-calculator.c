/* gcc -Wall crc32-calculator.c crc32.c memory.c -o crc32-calculator */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "crc32.h"

static void process_file(const char *filename)
{
	int i;
	FILE *fp;
	if (!(fp = fopen(filename, "rb"))) {
		fprintf(stderr, "! %s : %s\n", filename, strerror(errno));
		return;
	}
	fseek(fp, 0, SEEK_END);
	long size = ftell(fp);
	rewind(fp);

	printf("file name : %s, file size : %ld, CRC32: ", filename, size);
	unsigned char *buf = (unsigned char *) malloc(size);
	long count = fread(buf, 1, size, fp);
	assert(count == size);

	CRC32_t crc;
	CRC32_Init(&crc);
	CRC32_Update(&crc, buf, count);
	unsigned char crc_out[4];
	CRC32_Final(crc_out, crc);
	for (i = 0; i < 4; i++) {
		printf("%02x ", crc_out[i]);
	}
	printf("\n");
	fclose(fp);
}

int main(int argc, char **argv)
{
	int i;

	if (argc < 2) {
		printf("Usage: %s [files]\n", argv[0]);
		return 0;
	}
	for (i = 1; i < argc; i++)
		process_file(argv[i]);

	return 0;
}

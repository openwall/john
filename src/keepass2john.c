/* keepass2john utility (modified KeeCracker) written in March of 2012
 * by Dhiru Kholia. keepass2john processes input KeePass 1.x and 2.x
 * database files into a format suitable for use with JtR. This software
 * is Copyright © 2012, Dhiru Kholia <dhiru.kholia at gmail.com> and it
 * is hereby released under GPL license.
 *
 * KeePass 2.x support is based on KeeCracker - The KeePass 2 Database
 * Cracker, http://keecracker.mbw.name/
 *
 * KeePass 1.x support is based on kppy -  A Python-module to provide
 * an API to KeePass 1.x files. http://gitorious.org/kppy/kppy
 * Copyright (C) 2012 Karsten-Kai König <kkoenig@posteo.de>
 *
 * kppy is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or at your option) any later version.
 *
 * kppy is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * kppy. If not, see <http://www.gnu.org/licenses/>. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "params.h"

// KeePass 1.x signature
uint32_t FileSignatureOld1 = 0x9AA2D903;
uint32_t FileSignatureOld2 = 0xB54BFB65;
/// <summary>
/// File identifier, first 32-bit value.
/// </summary>
uint32_t FileSignature1 = 0x9AA2D903;
/// <summary>
/// File identifier, second 32-bit value.
/// </summary>
uint32_t FileSignature2 = 0xB54BFB67;
// KeePass 2.x pre-release (alpha and beta) signature
uint32_t FileSignaturePreRelease1 = 0x9AA2D903;
uint32_t FileSignaturePreRelease2 = 0xB54BFB66;
uint32_t FileVersionCriticalMask = 0xFFFF0000;
/// <summary>
/// File version of files saved by the current <c>Kdb4File</c> class.
/// KeePass 2.07 has version 1.01, 2.08 has 1.02, 2.09 has 2.00,
/// 2.10 has 2.02, 2.11 has 2.04, 2.15 has 3.00.
/// The first 2 bytes are critical (i.e. loading will fail, if the
/// file version is too high), the last 2 bytes are informational.
/// </summary>
uint32_t FileVersion32 = 0x00030000;

enum Kdb4HeaderFieldID
{
	EndOfHeader = 0,
	MasterSeed = 4,
	TransformSeed = 5,
	TransformRounds = 6,
	EncryptionIV = 7,
	StreamStartBytes = 9,
};

static off_t get_file_size(char * filename)
{
	struct stat sb;
	if (stat(filename, & sb) != 0) {
		fprintf(stderr, "! %s : stat failed, %s\n", filename, strerror(errno));
		exit(-2);
	}
	return sb.st_size;
}

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}

static uint64_t BytesToUInt64(unsigned char * s)
{
	uint64_t v = s[0];
	v |= (uint64_t)s[1] << 8;
	v |= (uint64_t)s[2] << 16;
	v |= (uint64_t)s[3] << 24;
	v |= (uint64_t)s[4] << 32;
	v |= (uint64_t)s[5] << 40;
	v |= (uint64_t)s[6] << 48;
	v |= (uint64_t)s[7] << 56;
	return v;
}

static uint32_t fget32(FILE * fp)
{
	uint32_t v = fgetc(fp);
	v |= fgetc(fp) << 8;
	v |= fgetc(fp) << 16;
	v |= fgetc(fp) << 24;
	return v;
}

static uint16_t fget16(FILE * fp)
{
	uint32_t v = fgetc(fp);
	v |= fgetc(fp) << 8;
	return v;
}

/* process KeePass 1.x databases */
static void process_old_database(FILE *fp, char* encryptedDatabase)
{
	uint32_t enc_flag;
	uint32_t version;
	unsigned char final_randomseed[16];
	unsigned char enc_iv[16];
	unsigned char contents_hash[32];
	unsigned char transf_randomseed[32];
	uint32_t num_groups;
	uint32_t num_entries;
	uint32_t key_transf_rounds;
	unsigned char buffer[LINE_BUFFER_SIZE];
	int count;
	long long filesize;
	long long datasize;
	enc_flag = fget32(fp);
	version = fget32(fp);
	count = fread(final_randomseed, 16, 1, fp);
	assert(count == 1);
	count = fread(enc_iv, 16, 1, fp);
	assert(count == 1);
	num_groups = fget32(fp);
	num_entries = fget32(fp);
	(void)num_groups;
	(void)num_entries;
	count = fread(contents_hash, 32, 1, fp);
	assert(count == 1);
	count = fread(transf_randomseed, 32, 1, fp);
	assert(count == 1);
	key_transf_rounds = fget32(fp);
	/* Check if the database is supported */
	if((version & 0xFFFFFF00) != (0x00030002 & 0xFFFFFF00)) {
		fprintf(stderr, "! %s : Unsupported file version!\n", encryptedDatabase);
		return;
	}
	else if(!(enc_flag & 2)) {
		fprintf(stderr, "! %s : Unsupported file encryption!\n", encryptedDatabase);
		return;
	}
	printf("%s:$keepass$*1*%d*%d*",encryptedDatabase, key_transf_rounds, 124);
	print_hex(final_randomseed, 16);
	printf("*");
	print_hex(transf_randomseed, 32);
	printf("*");
	print_hex(enc_iv, 16);
	printf("*");
	print_hex(contents_hash, 32);
	filesize = (long long)get_file_size(encryptedDatabase);
	datasize = filesize - 124;
	if(filesize < (LINE_BUFFER_SIZE - 128)) {
		/* we can inline the content with the hash */
		printf("*1*%lld*", datasize);
		fseek(fp, 124, SEEK_SET);
		count = fread(buffer, datasize, 1, fp);
		assert(count == 1);
		print_hex(buffer, datasize);
	}
	else {
		printf("*0*%s", encryptedDatabase); /* data is not inline */
	}
	printf("\n");
}

static void process_database(char* encryptedDatabase)
{
	long dataStartOffset;
	unsigned long transformRounds = 0;
	unsigned char *masterSeed = NULL;
	int masterSeedLength = 0;
	unsigned char *transformSeed = NULL;
	int transformSeedLength = 0;
	unsigned char *initializationVectors = NULL;
	int initializationVectorsLength = 0;
	unsigned char *expectedStartBytes = NULL;
	int endReached, expectedStartBytesLength = 0;
	uint32_t uSig1, uSig2, uVersion;
	FILE *fp;

	fp = fopen(encryptedDatabase, "rb");
	if (!fp) {
		fprintf(stderr, "! %s : %s\n", encryptedDatabase, strerror(errno));
		return;
	}
	uSig1 = fget32(fp);
	uSig2 = fget32(fp);
	if ((uSig1 == FileSignatureOld1) && (uSig2 == FileSignatureOld2)) {
		process_old_database(fp, encryptedDatabase);
		fclose(fp);
		return;
	}
	if ((uSig1 == FileSignature1) && (uSig2 == FileSignature2)) {
	}
	else if ((uSig1 == FileSignaturePreRelease1) && (uSig2 == FileSignaturePreRelease2)) {
	}
	else {
		fprintf(stderr, "! %s : Unknown format: File signature invalid\n", encryptedDatabase);
		fclose(fp);
		return;
	}
        uVersion = fget32(fp);
	if ((uVersion & FileVersionCriticalMask) > (FileVersion32 & FileVersionCriticalMask)) {
		fprintf(stderr, "! %s : Unknown format: File version unsupported\n", encryptedDatabase);
		fclose(fp);
		return;
	}
	endReached = 0;
	while (!endReached)
	{
		unsigned char btFieldID = fgetc(fp);
                uint16_t uSize = fget16(fp);
                enum Kdb4HeaderFieldID kdbID;
		unsigned char *pbData = NULL;

		if (uSize > 0)
		{
			pbData = (unsigned char*)malloc(uSize);
			if (fread(pbData, uSize, 1, fp) != 1)
				fprintf(stderr, "error reading pbData\n");
		}
		kdbID = btFieldID;
		switch (kdbID)
		{
			case EndOfHeader:
				endReached = 1;  // end of header
				free(pbData);
				break;

                        case MasterSeed:
				masterSeed = pbData;
				masterSeedLength = uSize;
				break;

                        case TransformSeed:
				transformSeed = pbData;
				transformSeedLength = uSize;
				break;

                        case TransformRounds:
				transformRounds = BytesToUInt64(pbData);
				free(pbData);
				break;

                        case EncryptionIV:
				initializationVectors = pbData;
				initializationVectorsLength = uSize;
				break;

                        case StreamStartBytes:
				expectedStartBytes = pbData;
				expectedStartBytesLength = uSize;
				break;

			default:
				free(pbData);
				break;
		}
	}
	dataStartOffset = ftell(fp);
	if(transformRounds == 0) {
		fprintf(stderr, "! %s : transformRounds can't be 0\n", encryptedDatabase);
		return;
	}
#ifdef KEEPASS_DEBUG
	fprintf(stderr, "%d, %d, %d, %d\n", masterSeedLength, transformSeedLength, initializationVectorsLength, expectedStartBytesLength);
#endif
	printf("%s:$keepass$*2*%ld*%ld*",encryptedDatabase, transformRounds, dataStartOffset);
	print_hex(masterSeed, masterSeedLength);
	printf("*");
	print_hex(transformSeed, transformSeedLength);
	printf("*");
	print_hex(initializationVectors, initializationVectorsLength);
	printf("*");
	print_hex(expectedStartBytes, expectedStartBytesLength);
	printf("\n");
	free(masterSeed);
	free(transformSeed);
	free(initializationVectors);
	free(expectedStartBytes);
	fclose(fp);
}

int keepass2john(int argc, char **argv)
{
	int i;

	if(argc < 2) {
		fprintf(stderr, "Usage: keepass2john [KeePass database(s)]\n");
		return -1;
	}
	for(i = 1; i < argc; i++) {
		process_database(argv[i]);
	}

	return 0;
}

/* bitlocker2john utility (modified KeeCracker) written in March of 2012
 * by Dhiru Kholia. keepass2john processes input KeePass 1.x and 2.x
 * database files into a format suitable for use with JtR. This software
 * is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com> and it
 * is hereby released under GPL license.
 *
 * KeePass 2.x support is based on KeeCracker - The KeePass 2 Database
 * Cracker, http://keecracker.mbw.name/
 *
 * KeePass 1.x support is based on kppy -  A Python-module to provide
 * an API to KeePass 1.x files. http://gitorious.org/kppy/kppy
 * Copyright (C) 2012 Karsten-Kai König <kkoenig@posteo.de>
 *
 * Keyfile support for Keepass 1.x and Keepass 2.x was added by Fist0urs
 * <eddy.maaalou at gmail.com>
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

#if AC_BUILT
#include "autoconfig.h"
#endif

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "stdint.h"
#ifdef _MSC_VER
#include "missing_getopt.h"
#endif
#include <errno.h>
// needs to be above sys/types.h and sys/stat.h for mingw, if -std=c99 used.
#include "jumbo.h"
#include <sys/stat.h>
#include <sys/types.h>
#if  (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>	// getopt defined here for unix
#endif
#include "params.h"
#include "memory.h"
#include "memdbg.h"

#include "sha2.h"
#include "base64.h"

#define BITLOCKER_HASH_SIZE 8  //32
#define BITLOCKER_ROUND_SHA_NUM 64
#define BITLOCKER_SINGLE_BLOCK_SHA_SIZE 64
#define BITLOCKER_SINGLE_BLOCK_W_SIZE 64
#define BITLOCKER_PADDING_SIZE 40
#define BITLOCKER_ITERATION_NUMBER 0x100000
#define BITLOCKER_WORD_SIZE 4
#define BITLOCKER_INPUT_SIZE 512
#define BITLOCKER_FIXED_PART_INPUT_CHAIN_HASH 88
#define BITLOCKER_BLOCK_UNIT 32
#define BITLOCKER_HASH_SIZE_STRING 32
#define BITLOCKER_MAX_INPUT_PASSWORD_LEN 16
#define BITLOCKER_MIN_INPUT_PASSWORD_LEN 8

#define AUTHENTICATOR_LENGTH 16
#define AES_CTX_LENGTH 256
#define FALSE 0
#define TRUE 1
#define BITLOCKER_SALT_SIZE 16
#define BITLOCKER_MAC_SIZE 16
#define BITLOCKER_NONCE_SIZE 12
#define BITLOCKER_IV_SIZE 16
#define BITLOCKER_VMK_SIZE 44
#ifndef UINT32_C
#define UINT32_C(c) c ## UL
#endif

static unsigned char salt_bitcracker[BITLOCKER_SALT_SIZE],
       mac[BITLOCKER_MAC_SIZE], 
       nonce[BITLOCKER_NONCE_SIZE],
       encryptedVMK[BITLOCKER_VMK_SIZE];

static char *keyfile = NULL;

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
static void warn_exit(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (fmt != NULL)
		vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

static void process_encrypted_image(char* encryptedImage)
{
/*
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
	unsigned char out[32];
	char *dbname;
*/

	FILE *fp;

	int match = 0;
	char signature[9] = "-FVE-FS-";
	int version = 0;
	unsigned char vmk_entry[4] = { 0x02, 0x00, 0x08, 0x00 };
	unsigned char key_protection_type[2] = { 0x00, 0x20 };
	unsigned char value_type[2] = { 0x00, 0x05 };
	char c;
	int i = 0;
	int j, fileLen;

	fp = fopen(encryptedImage, "r");
	if (!fp) {
		fprintf(stderr, "! %s : %s\n", encryptedImage, strerror(errno));
		return;
	}
	
	fseek(encryptedImage, 0, SEEK_END);
	fileLen = ftell(encryptedImage);
	fseek(encryptedImage, 0, SEEK_SET);
	for (j = 0; j < fileLen; j++) {
		c = fgetc(encryptedImage);
		while ((unsigned char)c == signature[i]) {
			c = fgetc(encryptedImage);
			i++;
		}
		if (i == 8) {
			match = 1;
			printf("[BitCracker] -> Signature found at 0x%08lx\n",
			       (ftell(encryptedImage) - i - 1));
			fseek(encryptedImage, 1, SEEK_CUR);
			version = fgetc(encryptedImage);
			printf("[BitCracker] -> Version: %d ", version);
			if (version == 1)
				printf("(Windows Vista)\n");
			else if (version == 2)
				printf("(Windows 7 or later)\n");
			else {
				printf
				("\nBitCracker] -> Invalid version, looking for a signature with valid version..\n");
			}
		}
		i = 0;
		while ((unsigned char)c == vmk_entry[i]) {
			c = fgetc(encryptedImage);
			i++;
		}
		if (i == 4) {
			printf("[BitCracker] -> VMK entry found at 0x%08lx\n",
			       (ftell(encryptedImage) - i - 3));
			fseek(encryptedImage, 27, SEEK_CUR);
			if (((unsigned char)fgetc(encryptedImage) == key_protection_type[0]) &&
			        ((unsigned char)fgetc(encryptedImage) == key_protection_type[1])) {
				printf
				("[BitCracker] -> Key protector with user password found\n");
				fseek(encryptedImage, 12, SEEK_CUR);
				fillBuffer(encryptedImage, salt_bitcracker, 16);
				printf("[BitCracker] -> Salt:");
				print_hex(salt_bitcracker, 16);
				fseek(encryptedImage, 83, SEEK_CUR);
				if (((unsigned char)fgetc(encryptedImage) != value_type[0]) ||
				        ((unsigned char)fgetc(encryptedImage) != value_type[1])) {
					error_msg("Error: VMK not encrypted with AES-CCM\n");
				}
				fseek(encryptedImage, 3, SEEK_CUR);
				fillBuffer(encryptedImage, nonce, 12);
				printf("[BitCracker] -> Nonce:");
				print_hex(nonce, 12);
				fillBuffer(encryptedImage, mac, 16);
				printf("[BitCracker] -> MAC:");
				print_hex(mac, 16);
				fillBuffer(encryptedImage, encryptedVMK, 44);
				printf("[BitCracker] -> Encrypted VMK:");
				print_hex(encryptedVMK, 44);
				break;
			}
		}
		i = 0;

	}
	fclose(encryptedImage);
	if (match == 0) {
		error_msg("Error while extracting data: No signature found!\n");
	}
	else
	{
		printf("BitLocker format hash: $bitlocker$");
		print_hex(nonce, BITLOCKER_NONCE_SIZE);
		printf("$");
		print_hex(salt, BITLOCKER_SALT_SIZE);
		printf("$");
		print_hex(encryptedVMK, 1);
		print_hex(encryptedVMK+1, 1);
		print_hex(encryptedVMK+8, 1);
		print_hex(encryptedVMK+9, 1);
		printf("$");
	}

#if 0
	/* specific to keyfile handling */
	unsigned char *buffer;
	long long filesize_keyfile = 0;
	char *p;
	char *data;
	char b64_decoded[64];
	FILE *kfp = NULL;
	SHA256_CTX ctx;
	unsigned char hash[32];
	int counter;

	
	uSig1 = fget32(fp);
	uSig2 = fget32(fp);
	if ((uSig1 == FileSignatureOld1) && (uSig2 == FileSignatureOld2)) {
		process_old_database(fp, encryptedImage);
		fclose(fp);
		return;
	}
	if ((uSig1 == FileSignature1) && (uSig2 == FileSignature2)) {
	}
	else if ((uSig1 == FileSignaturePreRelease1) && (uSig2 == FileSignaturePreRelease2)) {
	}
	else {
		fprintf(stderr, "! %s : Unknown format: File signature invalid\n", encryptedImage);
		fclose(fp);
		return;
	}
	uVersion = fget32(fp);
	if ((uVersion & FileVersionCriticalMask) > (FileVersion32 & FileVersionCriticalMask)) {
		fprintf(stderr, "! %s : Unknown format: File version unsupported\n", encryptedImage);
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
			pbData = (unsigned char*)mem_alloc(uSize);
			if (fread(pbData, uSize, 1, fp) != 1) {
				fprintf(stderr, "error reading pbData\n");
				MEM_FREE(pbData);
				goto bailout;
			}
		}
		kdbID = btFieldID;
		switch (kdbID)
		{
			case EndOfHeader:
				endReached = 1;  // end of header
				MEM_FREE(pbData);
				break;

			case MasterSeed:
				if (masterSeed)
					MEM_FREE(masterSeed);
				masterSeed = pbData;
				masterSeedLength = uSize;
				break;

			case TransformSeed:
				if (transformSeed)
					MEM_FREE(transformSeed);

				transformSeed = pbData;
				transformSeedLength = uSize;
				break;

			case TransformRounds:
				if (!pbData) {
					fprintf(stderr, "! %s : parsing failed (pbData is NULL), please open a bug if target is valid KeepPass database.\n", encryptedImage);
					goto bailout;
				}
				else {
					transformRounds = BytesToUInt64(pbData, uSize);
					MEM_FREE(pbData);
				}
				break;

			case EncryptionIV:
				if (initializationVectors)
					MEM_FREE(initializationVectors);
				initializationVectors = pbData;
				initializationVectorsLength = uSize;
				break;

			case StreamStartBytes:
				if (expectedStartBytes)
					MEM_FREE(expectedStartBytes);
				expectedStartBytes = pbData;
				expectedStartBytesLength = uSize;
				break;

			default:
				MEM_FREE(pbData);
				break;
		}
	}
	dataStartOffset = ftell(fp);
	if (transformRounds == 0) {
		fprintf(stderr, "! %s : transformRounds can't be 0\n", encryptedImage);
		goto bailout;
	}
#ifdef KEEPASS_DEBUG
	fprintf(stderr, "%d, %d, %d, %d\n", masterSeedLength, transformSeedLength, initializationVectorsLength, expectedStartBytesLength);
#endif
	if (!masterSeed || !transformSeed || !initializationVectors || !expectedStartBytes) {
		fprintf(stderr, "! %s : parsing failed, please open a bug if target is valid KeepPass database.\n", encryptedImage);
		goto bailout;
	}

	if (keyfile) {
		kfp = fopen(keyfile, "rb");
		if (!kfp) {
			fprintf(stderr, "! %s : %s\n", keyfile, strerror(errno));
			return;
		}
		filesize_keyfile = (long long)get_file_size(keyfile);
 	}

	dbname = strip_suffixes(basename(encryptedImage),extension, 1);
	printf("%s:$keepass$*2*%ld*%ld*",dbname, transformRounds, dataStartOffset);
	print_hex(masterSeed, masterSeedLength);
	printf("*");
	print_hex(transformSeed, transformSeedLength);
	printf("*");
	print_hex(initializationVectors, initializationVectorsLength);
	printf("*");
	print_hex(expectedStartBytes, expectedStartBytesLength);
	if (fread(out, 32, 1, fp) != 1) {
		fprintf(stderr, "error reading encrypted data!\n");
		goto bailout;
	}
	printf("*");
	print_hex(out, 32);

	if (keyfile) {
		buffer = (unsigned char*) mem_alloc (filesize_keyfile * sizeof(char));
		printf("*1*64*"); /* inline keyfile content */
		if (fread(buffer, filesize_keyfile, 1, kfp) != 1)
			warn_exit("%s: Error: read failed: %s.",
				encryptedImage, strerror(errno));

		/* as in Keepass 2.x implementation:
		 *  if keyfile is an xml, get <Data> content
		 *  if filesize_keyfile == 32 then assume byte_array
		 *  if filesize_keyfile == 64 then assume hex(byte_array)
		 *  else byte_array = sha256(keyfile_content)
		 */

		if (!memcmp((char *) buffer, "<?xml", 5)
			&& ((p = strstr((char *) buffer, "<Key>")) != NULL)
			&& ((p = strstr(p, "<Data>")) != NULL)
			)
		{
			p += strlen("<Data>");
			data = p;
			p = strstr(p, "</Data>");
			base64_decode(data, p - data, b64_decoded);
			print_hex((unsigned char *) b64_decoded, 32);
		}
		else if (filesize_keyfile == 32)
			print_hex(buffer, filesize_keyfile);
		else if (filesize_keyfile == 64)
		{
			for (counter = 0; counter <64; counter++)
				printf ("%c", buffer[counter]);
		}
		else
		{
		  /* precompute sha256 to speed-up cracking */

		  SHA256_Init(&ctx);
		  SHA256_Update(&ctx, buffer, filesize_keyfile);
		  SHA256_Final(hash, &ctx);
		  print_hex(hash, 32);
		}
		MEM_FREE(buffer);
	}
	printf("\n");

bailout:
	MEM_FREE(masterSeed);
	MEM_FREE(transformSeed);
	MEM_FREE(initializationVectors);
	MEM_FREE(expectedStartBytes);
	fclose(fp);
#endif
}

static int usage(char *name)
{
	fprintf(stderr, "Usage: %s [-k <keyfile>] <BitLocker Encrypted Memory Image>\n", name);

	return EXIT_FAILURE;
}

int keepass2john(int argc, char **argv)
{
	int c;

	errno = 0;
	/* Parse command line */
	while ((c = getopt(argc, argv, "k:")) != -1) {
		switch (c) {
		case 'k':
			keyfile = (char *)mem_alloc(strlen(optarg) + 1);
			strcpy(keyfile, optarg);
			break;
		case '?':
		default:
			return usage(argv[0]);
		}
	}
	argc -= optind;
	if (argc == 0)
		return usage(argv[0]);
	argv += optind;

	while(argc--)
		process_encrypted_image(*argv++);

	MEMDBG_PROGRAM_EXIT_CHECKS(stderr);
	return 0;
}

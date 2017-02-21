/* bitlocker2john utility written in February of 2017 by Elenago <elena dot ago at gmail dot com>.
 * bitlocker2john processes input memory images encrypted with BitLocker. by means of a password,
 * into a format suitable for use with JtR. This software
 * is Copyright (c) 2017, Elenago <elena dot ago at gmail dot com> and it
 * is hereby released under GPLv2 license.
 * This is a research project, therefore please cite or contact me if you want to use it
 *
 * bitlocker2john is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * More informations here: http://openwall.info/wiki/john/OpenCL-BitLocker
 *
 */

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
#include "jumbo.h"
#include <sys/stat.h>
#include <sys/types.h>
#if  (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>             // getopt defined here for unix
#endif
#include "params.h"
#include "memory.h"
#include "memdbg.h"

#include "sha2.h"
#include "base64.h"

#define BITLOCKER_HASH_SIZE 8   //32
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
#define BITLOCKER_NONCE_SIZE 12
#define BITLOCKER_IV_SIZE 16
#define BITLOCKER_VMK_SIZE 44
#ifndef UINT32_C
#define UINT32_C(c) c ## UL
#endif

static unsigned char salt[BITLOCKER_SALT_SIZE],
       nonce[BITLOCKER_NONCE_SIZE], 
       encryptedVMK[BITLOCKER_VMK_SIZE];

static void fillBuffer(FILE *fp, unsigned char *buffer, int size);

static char *outFile = NULL;

static void fillBuffer(FILE *fp, unsigned char *buffer, int size)
{
	int k;

	for (k = 0; k < size; k++) {
		buffer[k] = (unsigned char)fgetc(fp);
	}
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

static void process_encrypted_image(char *encryptedImagePath)
{
	FILE *encryptedImage, *ofp;

	int match = 0;
	char signature[9] = "-FVE-FS-";
	int version = 0;
	unsigned char vmk_entry[4] = { 0x02, 0x00, 0x08, 0x00 };
	unsigned char key_protection_type[2] = { 0x00, 0x20 };
	unsigned char value_type[2] = { 0x00, 0x05 };
	char c;
	int i = 0;
	int j, fileLen;

	encryptedImage = fopen(encryptedImagePath, "r");
	if (!encryptedImage) {
		fprintf(stderr, "! %s : %s\n", encryptedImagePath, strerror(errno));
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
			printf("Signature found at 0x%08lx\n",
			       (ftell(encryptedImage) - i - 1));
			fseek(encryptedImage, 1, SEEK_CUR);
			version = fgetc(encryptedImage);
			printf("Version: %d ", version);
			if (version == 1)
				printf("(Windows Vista)\n");
			else if (version == 2)
				printf("(Windows 7 or later)\n");
			else {
				printf
				("\nInvalid version, looking for a signature with valid version..\n");
			}
		}
		i = 0;
		while ((unsigned char)c == vmk_entry[i]) {
			c = fgetc(encryptedImage);
			i++;
		}
		if (i == 4) {
			printf("VMK entry found at 0x%08lx\n",
			       (ftell(encryptedImage) - i - 3));
			fseek(encryptedImage, 27, SEEK_CUR);
			if (((unsigned char)fgetc(encryptedImage) ==
			        key_protection_type[0]) &&
			        ((unsigned char)fgetc(encryptedImage) ==
			         key_protection_type[1])) {
				printf("Key protector with user password found\n");
				fseek(encryptedImage, 12, SEEK_CUR);
				fillBuffer(encryptedImage, salt, BITLOCKER_SALT_SIZE);
				fseek(encryptedImage, 83, SEEK_CUR);
				if (((unsigned char)fgetc(encryptedImage) != value_type[0]) ||
				        ((unsigned char)fgetc(encryptedImage) != value_type[1])) {
					warn_exit("Error: VMK not encrypted with AES-CCM\n");
				}
				fseek(encryptedImage, 3, SEEK_CUR);
				fillBuffer(encryptedImage, nonce, BITLOCKER_NONCE_SIZE);
				fillBuffer(encryptedImage, encryptedVMK, BITLOCKER_VMK_SIZE);
				break;
			}
		}
		i = 0;

	}
	fclose(encryptedImage);
	if (match == 0) {
		warn_exit("Error while extracting data: No signature found!\n");
	} else {
		printf("\n\nBitLocker-OpenCL format hash: $bitlocker$");
		print_hex(nonce, BITLOCKER_NONCE_SIZE);
		printf("$");
		print_hex(salt, BITLOCKER_SALT_SIZE);
		printf("$");
		print_hex(encryptedVMK, 1);
		print_hex(encryptedVMK + 1, 1);
		print_hex(encryptedVMK + 8, 1);
		print_hex(encryptedVMK + 9, 1);
		printf("\n\n");

		if (outFile) {
			ofp = fopen(outFile, "w");
			if (!ofp) {
				fprintf(stderr, "! %s : %s\n", outFile, strerror(errno));
				return;
			}
			//This is super ugly...!
			fprintf(ofp,
			        "$bitlocker$%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x$%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x$%02x%02x%02x%02x\n",
			        nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5],
			        nonce[6], nonce[7], nonce[8], nonce[9], nonce[10], nonce[11],
			        salt[0], salt[1], salt[2],
			        salt[3], salt[4], salt[5],
			        salt[6], salt[7], salt[8],
			        salt[9], salt[10], salt[11],
			        salt[12], salt[13], salt[14],
			        salt[15], encryptedVMK[0], encryptedVMK[1],
			        encryptedVMK[8], encryptedVMK[9]);

			fclose(ofp);
		}
	}
}

static int usage(char *name)
{
	fprintf(stderr,
	        "Usage: %s [-o <output_file>] <BitLocker Encrypted Memory Image>\n",
	        name);

	return EXIT_FAILURE;
}

int bitlocker2john(int argc, char **argv)
{
	int c;

	errno = 0;

	/* Parse command line */
	while ((c = getopt(argc, argv, "o:")) != -1) {
		switch (c) {
		case 'o':
			outFile = (char *)mem_alloc(strlen(optarg) + 1);
			strcpy(outFile, optarg);
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

	while (argc--)
		process_encrypted_image(*argv++);

	MEMDBG_PROGRAM_EXIT_CHECKS(stderr);
	return 0;
}

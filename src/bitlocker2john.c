/*
 * bitlocker2john processes input disk images encrypted with BitLocker, by
 * means of a password, into a format suitable for use with JtR.
 *
 * This software is Copyright (c) 2017, Elenago <elena dot ago at gmail dot com> and
 * it is hereby released under GPLv2 license.
 *
 * bitlocker2john is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * More informations here: http://openwall.info/wiki/john/OpenCL-BitLocker
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef _MSC_VER
#include "missing_getopt.h"
#endif
#include <errno.h>
#include "jumbo.h"
#include <sys/stat.h>
#include <sys/types.h>
#if  (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h> // getopt defined here for unix
#endif
#include "params.h"
#include "memory.h"
#include "memdbg.h"

#define BITLOCKER_SALT_SIZE 16
#define BITLOCKER_NONCE_SIZE 12
#define BITLOCKER_VMK_SIZE 44
#define BITLOCKER_MAC_SIZE 16

static unsigned char salt[BITLOCKER_SALT_SIZE],
		nonce[BITLOCKER_NONCE_SIZE],
		mac[BITLOCKER_MAC_SIZE],
		encryptedVMK[BITLOCKER_VMK_SIZE];

static void fillBuffer(FILE *fp, unsigned char *buffer, int size)
{
	int k;

	for (k = 0; k < size; k++)
		buffer[k] = (unsigned char)fgetc(fp);
}

static void print_hex(unsigned char *str, int len)
{
	int i;

	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}

static void process_encrypted_image(char *encryptedImagePath)
{
	FILE *encryptedImage;

	int match = 0;
	char signature[8] = "-FVE-FS-";
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
		while (i < 8 && (unsigned char)c == signature[i]) {
			c = fgetc(encryptedImage);
			i++;
		}
		if (i == 8) {
			match = 1;
			fprintf(stderr, "Signature found at 0x%08lx\n",
					(ftell(encryptedImage) - i - 1));
			fseek(encryptedImage, 1, SEEK_CUR);
			version = fgetc(encryptedImage);
			fprintf(stderr, "Version: %d ", version);
			if (version == 1)
				fprintf(stderr, "(Windows Vista)\n");
			else if (version == 2)
				fprintf(stderr, "(Windows 7 or later)\n");
			else {
				fprintf
					(stderr, "\nInvalid version, looking for a signature with valid version...\n");
			}
		}
		i = 0;
		while (i < 4 && (unsigned char)c == vmk_entry[i]) {
			c = fgetc(encryptedImage);
			i++;
		}
		if (i == 4) {
			fprintf(stderr, "VMK entry found at 0x%08lx\n",
					(ftell(encryptedImage) - i - 3));
			fseek(encryptedImage, 27, SEEK_CUR);
			if (
					((unsigned char)fgetc(encryptedImage) == key_protection_type[0]) &&
					((unsigned char)fgetc(encryptedImage) == key_protection_type[1])
			   ) {
				fprintf(stderr, "Key protector with user password found\n");
				fseek(encryptedImage, 12, SEEK_CUR);
				fillBuffer(encryptedImage, salt, BITLOCKER_SALT_SIZE);
				fseek(encryptedImage, 83, SEEK_CUR);
				if (((unsigned char)fgetc(encryptedImage) != value_type[0]) ||
						((unsigned char)fgetc(encryptedImage) != value_type[1])) {
					fprintf(stderr, "Error: VMK not encrypted with AES-CCM\n");
				}
				fseek(encryptedImage, 3, SEEK_CUR);
				fillBuffer(encryptedImage, nonce, BITLOCKER_NONCE_SIZE);
				fillBuffer(encryptedImage, mac, BITLOCKER_MAC_SIZE);
				fillBuffer(encryptedImage, encryptedVMK, BITLOCKER_VMK_SIZE);
				break;
			}
		}
		i = 0;

	}
	fclose(encryptedImage);
	if (match == 0) {
#ifndef HAVE_LIBFUZZER
		fprintf(stderr, "Error while extracting data: No signature found!\n");
#endif
	} else {
		unsigned char padding[16] = {0};
		printf("%s:$bitlocker$0$%d$", encryptedImagePath, BITLOCKER_SALT_SIZE);
		print_hex(salt, BITLOCKER_SALT_SIZE);
		printf("$%d$%d$", 0x100000, BITLOCKER_NONCE_SIZE); // fixed iterations , fixed nonce size
		print_hex(nonce, BITLOCKER_NONCE_SIZE);
		printf("$%d$", BITLOCKER_VMK_SIZE + 16);
		print_hex(padding, 16); // hack, this should actually be entire AES-CCM encrypted block (which includes encryptedVMK)
		print_hex(encryptedVMK, BITLOCKER_VMK_SIZE);
		printf("\n");
	}
}

#ifdef HAVE_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int fd;
	char name[] = "/tmp/libFuzzer-XXXXXX";

	fd = mkstemp(name);
	if (fd < 0) {
		fprintf(stderr, "Problem detected while creating the input file, %s, aborting!\n", strerror(errno));
		exit(-1);
	}
	write(fd, data, size);
	close(fd);
	process_encrypted_image(name);
	remove(name);

	return 0;
}
#else
static int usage(char *name)
{
	fprintf(stderr,
			"Usage: %s <BitLocker Encrypted Disk Image(s)>\n",
			name);

	return EXIT_FAILURE;
}

int main(int argc, char **argv)
{
	errno = 0;

	if (argc < 2)
		return usage(argv[0]);
	argv++;
	argc--;
	while (argc--)
		process_encrypted_image(*argv++);

	MEMDBG_PROGRAM_EXIT_CHECKS(stderr);
	return 0;
}
#endif  // HAVE_LIBFUZZER

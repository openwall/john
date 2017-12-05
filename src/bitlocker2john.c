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

#define SALT_SIZE 16
#define NONCE_SIZE 12
#define VMK_SIZE 44
#define MAC_SIZE 16
#define SIGNATURE_LEN 9
#define INPUT_SIZE 2048

static unsigned char salt[SALT_SIZE], nonce[NONCE_SIZE], mac[MAC_SIZE], vmk[VMK_SIZE];

void * Calloc(size_t len, size_t size) {
	void * ptr = NULL;
	if ( size <= 0)
	{
		fprintf(stderr,"Critical error: memory size is 0\n");
		exit(EXIT_FAILURE);
	}

	ptr = (void *)calloc(len, size);	
	if ( ptr == NULL )
	{
		fprintf(stderr,"Critical error: Memory allocation\n");
		exit(EXIT_FAILURE);
	}
	return ptr;
}

static void fillBuffer(FILE *fp, unsigned char *buffer, int size)
{
	int k;

	for (k = 0; k < size; k++)
		buffer[k] = (unsigned char)fgetc(fp);
}

static void print_hex(unsigned char *str, int len, FILE *out)
{
	int i;

	for (i = 0; i < len; ++i)
		fprintf(out, "%02x", str[i]);
}

int process_encrypted_image(char * encryptedImagePath, char * outputFile)
{
	const char signature[SIGNATURE_LEN] = "-FVE-FS-";
	int version = 0, fileLen = 0, j = 0, i = 0, match = 0;

	unsigned char vmk_entry[4] = { 0x02, 0x00, 0x08, 0x00 };
	unsigned char key_protection_clear[2] = { 0x00, 0x00 };
	unsigned char key_protection_tpm[2] = { 0x00, 0x01 };
	unsigned char key_protection_start_key[2] = { 0x00, 0x02 };
	unsigned char key_protection_recovery[2] = { 0x00, 0x08 };
	unsigned char key_protection_password[2] = { 0x00, 0x20 };
	unsigned char value_type[2] = { 0x00, 0x05 };
	unsigned char padding[16] = {0};
	char c,d;
	FILE * outFile, * encryptedImage;


	printf("Opening file %s\n", encryptedImagePath);
	encryptedImage = fopen(encryptedImagePath, "r");
	if (!encryptedImage) {
		fprintf(stderr, "! %s : %s\n", encryptedImagePath, strerror(errno));
		return 1;
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
			fprintf(stderr, "\nSignature found at 0x%08lx\n", (ftell(encryptedImage) - i - 1));
			fseek(encryptedImage, 1, SEEK_CUR);
			version = fgetc(encryptedImage);
			fprintf(stderr, "Version: %d ", version);
			if (version == 1)
				fprintf(stderr, "(Windows Vista)\n");
			else if (version == 2)
				fprintf(stderr, "(Windows 7 or later)\n");
			else {
				fprintf(stderr, "\nInvalid version, looking for a signature with valid version...\n");
				match = 0;
			}
		}
		if (match == 0) { i=0; continue; }

		i = 0;
		while (i < 4 && (unsigned char)c == vmk_entry[i]) {
			c = fgetc(encryptedImage);
			i++;
		}

		if (i == 4) {
			fprintf(stderr, "VMK entry found at 0x%08lx\n", (ftell(encryptedImage) - i - 3));
			fseek(encryptedImage, 27, SEEK_CUR);
			c = (unsigned char)fgetc(encryptedImage);
			d = (unsigned char)fgetc(encryptedImage);

			if ((c == key_protection_clear[0]) && (d == key_protection_clear[1])) 
				fprintf(stderr, "VMK not encrypted.. stored clear!\n");
			else if ((c == key_protection_tpm[0]) && (d == key_protection_tpm[1])) 
				fprintf(stderr, "VMK encrypted with TPM...not supported!\n");
			else if ((c == key_protection_start_key[0]) && (d == key_protection_start_key[1])) 
				fprintf(stderr, "VMK encrypted with Startup Key...not supported!\n");
			else if ((c == key_protection_recovery[0]) && (d == key_protection_recovery[1])) 
				fprintf(stderr, "VMK encrypted with Recovery key...not supported!\n");
			else if ((c == key_protection_password[0]) && (d == key_protection_password[1])) 
			{
				fprintf(stderr, "VMK encrypted with user password found!\n");
				fseek(encryptedImage, 12, SEEK_CUR);
				fillBuffer(encryptedImage, salt, SALT_SIZE);
				fseek(encryptedImage, 83, SEEK_CUR);
				if (((unsigned char)fgetc(encryptedImage) != value_type[0]) || ((unsigned char)fgetc(encryptedImage) != value_type[1])) {
					fprintf(stderr, "Error: VMK not encrypted with AES-CCM\n");
					match=0;
					i=0;
					continue;
				}

				fseek(encryptedImage, 3, SEEK_CUR);
				fillBuffer(encryptedImage, nonce, NONCE_SIZE);
				fillBuffer(encryptedImage, mac, MAC_SIZE);
				fillBuffer(encryptedImage, vmk, VMK_SIZE);
				break;
			}
		}

		i = 0;
	}

	fclose(encryptedImage);

	if (match == 0) {
#ifndef HAVE_LIBFUZZER
		fprintf(stderr, "Error while extracting data: No signature found!\n");
		return 1;
#endif
	} else {
		printf("%s result hash:\n$bitlocker$0$%d$", encryptedImagePath, SALT_SIZE);
		print_hex(salt, SALT_SIZE, stdout);
		printf("$%d$%d$", 0x100000, NONCE_SIZE); // fixed iterations , fixed nonce size
		print_hex(nonce, NONCE_SIZE, stdout);
		printf("$%d$", VMK_SIZE + 16);
		print_hex(padding, 16, stdout); // hack, this should actually be entire AES-CCM encrypted block (which includes vmk)
		print_hex(vmk, VMK_SIZE, stdout);
		printf("\n");
		
		outFile = fopen(outputFile, "w");
		if (!outFile) {
			fprintf(stderr, "! %s : %s\n", outputFile, strerror(errno));
			return 1;
		}

		fprintf(outFile, "$bitlocker$0$%d$", SALT_SIZE);
		print_hex(salt, SALT_SIZE, outFile);
		fprintf(outFile, "$%d$%d$", 0x100000, NONCE_SIZE); // fixed iterations , fixed nonce size
		print_hex(nonce, NONCE_SIZE, outFile);
		fprintf(outFile, "$%d$", VMK_SIZE + 16);
		print_hex(padding, 16, outFile); // hack, this should actually be entire AES-CCM encrypted block (which includes vmk)
		print_hex(vmk, VMK_SIZE, outFile);
		fprintf(outFile, "\n");

		fclose(outFile);
	}

	return 0;
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

static int usage(char *name){
	printf("\nUsage: %s -i <Encrypted memory unit> -o <output file>\n\n"
		"Options:\n\n"
		"  -h"
		"\t\tShow this help\n"
		"  -i"
		"\t\tPath of memory unit encrypted with BitLocker\n"
		"  -o"
		"\t\tOutput file\n\n", name);

	return EXIT_FAILURE;
}

int main(int argc, char **argv)
{
	int opt = 0;
	char * imagePath=NULL, * outFile=NULL;
	
	errno = 0;
	while (1) {
		opt = getopt(argc, argv, "hi:o:");
		if (opt == -1)
			break;
		switch (opt)
		{
			case 'h':
				usage(argv[0]);
				exit(EXIT_FAILURE);
				break;
			case 'i':
				if (strlen(optarg) >= INPUT_SIZE)
				{
					fprintf(stderr, "ERROR: Input image path is bigger than %d\n", INPUT_SIZE);
					exit(EXIT_FAILURE);
				}
				imagePath=(char *)Calloc(INPUT_SIZE, sizeof(char));
				strncpy(imagePath, optarg, strlen(optarg)+1);
				break;
			case 'o':
				if (strlen(optarg) >= INPUT_SIZE)
				{
					fprintf(stderr, "ERROR: Input outfile path is bigger than %d\n", INPUT_SIZE);
					exit(EXIT_FAILURE);
				}
				outFile=(char *)Calloc(INPUT_SIZE, sizeof(char));
				strncpy(outFile,optarg, strlen(optarg)+1);
				break;
			default:
				break;
		}
	}

	if (!imagePath || !outFile)
	{
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	
	process_encrypted_image(imagePath, outFile);

	MEMDBG_PROGRAM_EXIT_CHECKS(stderr);

	return 0;
}

#endif  // HAVE_LIBFUZZER

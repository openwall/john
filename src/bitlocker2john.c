/*
 * The bitlocker2john utility processes input disk images encrypted with
 * BitLocker, by means of a password, into a format suitable for use with JtR.
 *
 * This software is Copyright (c) 2017, Elenago <elena dot ago at gmail dot com> and
 * it is hereby released under GPLv2 license.
 *
 * bitlocker2john is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * More info here: http://openwall.info/wiki/john/OpenCL-BitLocker
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef _MSC_VER
#include "missing_getopt.h"
#endif
#include "jumbo.h"
#if  (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h> // getopt defined here for unix
#endif
#include "params.h"
#include "memory.h"
#include "memdbg.h"

#define HASH_UP                  0
#define HASH_UP_MAC              1
#define HASH_RP                  2
#define HASH_RP_MAC              3

#define INPUT_SIZE               1024
#define SALT_SIZE                16
#define MAC_SIZE                 16
#define NONCE_SIZE               12
#define IV_SIZE                  16
#define VMK_SIZE                 44
#define SIGNATURE_LEN            9

static unsigned char p_salt[SALT_SIZE], p_nonce[NONCE_SIZE], p_mac[MAC_SIZE], p_vmk[VMK_SIZE];
static unsigned char r_salt[SALT_SIZE], r_nonce[NONCE_SIZE], r_mac[MAC_SIZE], r_vmk[VMK_SIZE];

static void fill_buffer(FILE *fp, unsigned char *buffer, int size)
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

int process_encrypted_image(char *image_path)
{
	int version = 0, i = 0, match = 0, vmk_found = 0, recovery_found = 0;
	long int file_length = 0, j = 0;
	const char signature[SIGNATURE_LEN] = "-FVE-FS-";
	unsigned char vmk_entry[4] = { 0x02, 0x00, 0x08, 0x00 };
	unsigned char key_protection_clear[2] = { 0x00, 0x00 };
	unsigned char key_protection_tpm[2] = { 0x00, 0x01 };
	unsigned char key_protection_start_key[2] = { 0x00, 0x02 };
	unsigned char key_protection_recovery[2] = { 0x00, 0x08 };
	unsigned char key_protection_password[2] = { 0x00, 0x20 };
	unsigned char value_type[2] = { 0x00, 0x05 };
	char a, b, c, d;
	FILE *fp;

	fprintf(stderr, "Opening file %s\n", image_path);
	fp = fopen(image_path, "r");

	if (!fp) {
		fprintf(stderr, "! %s : %s\n", image_path, strerror(errno));
		return 1;
	}

	fseek(fp, 0, SEEK_END);
	file_length = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	for (j = 0; j < file_length; j++) {
		c = fgetc(fp);
		while (i < 8 && (unsigned char)c == signature[i]) {
			c = fgetc(fp);
			i++;
		}
		if (i == 8) {
			match = 1;
			fprintf(stderr, "\nSignature found at 0x%08lx\n", (ftell(fp) - i - 1));
			fseek(fp, 1, SEEK_CUR);
			version = fgetc(fp);
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
		if (match == 0) {
			i = 0;
			continue;
		}
		i = 0;
		while (i < 4 && (unsigned char)c == vmk_entry[i]) {
			c = fgetc(fp);
			i++;
		}
		if (i == 4) {
			fprintf(stderr, "\nVMK entry found at 0x%08lx\n", (ftell(fp) - i - 3));
			fseek(fp, 27, SEEK_CUR);
			c = (unsigned char)fgetc(fp);
			d = (unsigned char)fgetc(fp);

			if ((c == key_protection_clear[0]) && (d == key_protection_clear[1]))
				fprintf(stderr, "VMK not encrypted.. stored clear!\n");
			else if ((c == key_protection_tpm[0]) && (d == key_protection_tpm[1]))
				fprintf(stderr, "VMK encrypted with TPM...not supported!\n");
			else if ((c == key_protection_start_key[0]) && (d == key_protection_start_key[1]))
				fprintf(stderr, "VMK encrypted with Startup Key...not supported!\n");
			else if ((c == key_protection_recovery[0]) && (d == key_protection_recovery[1])) {
				fprintf(stderr, "VMK encrypted with Recovery key found!\n");
				fseek(fp, 12, SEEK_CUR);
				fill_buffer(fp, r_salt, SALT_SIZE);
				fseek(fp, 147, SEEK_CUR);
				a = (unsigned char)fgetc(fp);
				b = (unsigned char)fgetc(fp);
				if ((a != value_type[0]) || (b != value_type[1])) {
					fprintf(stderr, "Error: VMK not encrypted with AES-CCM, a: %02x, b: %02x\n",a ,b);
					match = 0;
					i = 0;
					continue;
				} else
					fprintf(stderr, "VMK encrypted with AES-CCM\n");

				fseek(fp, 3, SEEK_CUR);
				fill_buffer(fp, r_nonce, NONCE_SIZE);
				fill_buffer(fp, r_mac, MAC_SIZE);
				fill_buffer(fp, r_vmk, VMK_SIZE);
				recovery_found = 1;
			}
			else if ((c == key_protection_password[0]) && (d == key_protection_password[1]) && vmk_found == 0) {
				fprintf(stderr, "VMK encrypted with user password found!\n");
				fseek(fp, 12, SEEK_CUR);
				fill_buffer(fp, p_salt, SALT_SIZE);
				fseek(fp, 83, SEEK_CUR);
				if (((unsigned char)fgetc(fp) != value_type[0]) || ((unsigned char)fgetc(fp) != value_type[1])) {
					fprintf(stderr, "Error: VMK not encrypted with AES-CCM\n");
					match = 0;
					i = 0;
					continue;
				}
				else fprintf(stderr, "VMK encrypted with AES-CCM\n");

				fseek(fp, 3, SEEK_CUR);
				fill_buffer(fp, p_nonce, NONCE_SIZE);
				fill_buffer(fp, p_mac, MAC_SIZE);
				fill_buffer(fp, p_vmk, VMK_SIZE);
				vmk_found = 1;
			}
		}

		i = 0;
		if (vmk_found == 1 && recovery_found == 1)
			break;
	}

	fclose(fp);

	if (vmk_found == 0 && recovery_found == 0) {
#ifndef HAVE_LIBFUZZER
		fprintf(stderr, "Error while extracting data: No signature found!\n");
		return 1;
#endif
	} else {
		if (vmk_found == 1) {
			// UP
			printf("\nUser Password hash:\n$bitlocker$%d$%d$", HASH_UP, SALT_SIZE);
			printf("$bitlocker$%d$%d$", HASH_UP, SALT_SIZE);
			print_hex(p_salt, SALT_SIZE, stdout);
			printf("$%d$%d$", 0x100000, NONCE_SIZE); // fixed iterations , fixed nonce size
			print_hex(p_nonce, NONCE_SIZE, stdout);
			printf("$%d$", VMK_SIZE + MAC_SIZE);
			print_hex(p_mac, MAC_SIZE, stdout);
			print_hex(p_vmk, VMK_SIZE, stdout);
			printf("\n");

			// UP with MAC
			printf("Hash type: User Password with MAC verification (slower solution, no false positives)\n");
			printf("$bitlocker$%d$%d$", HASH_UP_MAC, SALT_SIZE);
			print_hex(p_salt, SALT_SIZE, stdout);
			printf("$%d$%d$", 0x100000, NONCE_SIZE); // fixed iterations , fixed nonce size
			print_hex(p_nonce, NONCE_SIZE, stdout);
			printf("$%d$", VMK_SIZE + MAC_SIZE);
			print_hex(p_mac, MAC_SIZE, stdout);
			print_hex(p_vmk, VMK_SIZE, stdout);
			printf("\n");
		}

		if (recovery_found == 1) {
			// RP
			printf("Hash type: Recovery Password fast attack\n");
			printf("$bitlocker$%d$%d$", HASH_RP, SALT_SIZE);
			print_hex(r_salt, SALT_SIZE, stdout);
			printf("$%d$%d$", 0x100000, NONCE_SIZE); // fixed iterations , fixed nonce size
			print_hex(r_nonce, NONCE_SIZE, stdout);
			printf("$%d$", VMK_SIZE + MAC_SIZE);
			print_hex(r_mac, MAC_SIZE, stdout);
			print_hex(r_vmk, VMK_SIZE, stdout);
			printf("\n");

			// RP with MAC
			printf("Hash type: Recovery Password with MAC verification (slower solution, no false positives)\n");
			printf("$bitlocker$%d$%d$", HASH_RP_MAC, SALT_SIZE);
			print_hex(r_salt, SALT_SIZE, stdout);
			printf("$%d$%d$", 0x100000, NONCE_SIZE);
			print_hex(r_nonce, NONCE_SIZE, stdout);
			printf("$%d$", VMK_SIZE + MAC_SIZE);
			print_hex(r_mac, MAC_SIZE, stdout);
			print_hex(r_vmk, VMK_SIZE, stdout);
			printf("\n");
		}
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
	printf("\nUsage: %s -i <Image of encrypted memory unit>\n\n"
		"Options:\n\n"
		"  -h"
		"\t\tShow this help\n"
		"  -i"
		"\t\tImage path of encrypted memory unit encrypted with BitLocker\n", name);

	return EXIT_FAILURE;
}

int main(int argc, char **argv)
{
	int opt;
	char *image_path = NULL;

	errno = 0;

	while (1) {
		opt = getopt(argc, argv, "hi:");
		if (opt == -1)
			break;
		switch (opt) {
			case 'h':
				usage(argv[0]);
				exit(EXIT_FAILURE);
				break;

			case 'i':
				if (strlen(optarg) >= INPUT_SIZE) {
					fprintf(stderr, "ERROR: Input string is bigger than %d\n", INPUT_SIZE);
					exit(EXIT_FAILURE);
				}
				image_path = strdup(optarg);
				break;

			default:
				break;
		}
	}

	if (!image_path) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	process_encrypted_image(image_path);

	MEM_FREE(image_path);

	MEMDBG_PROGRAM_EXIT_CHECKS(stderr);

	return 0;
}

#endif  // HAVE_LIBFUZZER

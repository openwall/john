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

#define FRET_CHECK(ret)									\
	if (ret < 0)									\
	{										\
		fprintf(stderr, "ftell error %s (%d)\n", strerror(errno),errno);	\
		exit(EXIT_FAILURE);							\
	}


static unsigned char p_salt[SALT_SIZE], p_nonce[NONCE_SIZE], p_mac[MAC_SIZE], p_vmk[VMK_SIZE];
static unsigned char r_salt[SALT_SIZE], r_nonce[NONCE_SIZE], r_mac[MAC_SIZE], r_vmk[VMK_SIZE];

//Fixed
static unsigned char p_salt[SALT_SIZE], p_nonce[NONCE_SIZE], p_mac[MAC_SIZE], p_vmk[VMK_SIZE];
static unsigned char r_salt[SALT_SIZE], r_nonce[NONCE_SIZE], r_mac[MAC_SIZE], r_vmk[VMK_SIZE];
const char signature[SIGNATURE_LEN] = "-FVE-FS-";
unsigned char vmk_entry[4] = { 0x02, 0x00, 0x08, 0x00 };
unsigned char key_protection_clear[2] = { 0x00, 0x00 };
unsigned char key_protection_tpm[2] = { 0x00, 0x01 };
unsigned char key_protection_start_key[2] = { 0x00, 0x02 };
unsigned char key_protection_recovery[2] = { 0x00, 0x08 };
unsigned char key_protection_password[2] = { 0x00, 0x20 };
unsigned char value_type[2] = { 0x00, 0x05 };
unsigned char padding[16] = {0};

int userPasswordFound = 0, recoveryPasswordFound = 0, found_ccm = 0;
int64_t fp_before_aes = 0, fp_before_salt = 0;
FILE *fp_eimg;
int salt_pos[2] = {12, 32};
int aes_pos[1] = {147};

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

static int rp_search_salt_aes(void)
{
	uint8_t a,b;
	int64_t ret;
	int x, y;

	for (x = 0; x < 2; x++) {
		ret = jtr_fseek64(fp_eimg, salt_pos[x], SEEK_CUR);
		FRET_CHECK(ret)

		fillBuffer(fp_eimg, r_salt, SALT_SIZE);
		printf("Salt: ");
		print_hex(r_salt, SALT_SIZE, stdout);
		printf("\n");
		fp_before_aes = jtr_ftell64(fp_eimg);
		FRET_CHECK(fp_before_aes)
		fprintf(stderr, "Searching AES-CCM from 0x%llx\n", (unsigned long long)fp_before_aes);

		for (y = 0; y < 1; y++) {
			ret = jtr_fseek64(fp_eimg, aes_pos[y], SEEK_CUR);
			FRET_CHECK(ret)

			fprintf(stderr, "Trying offset 0x%llx....\n", (unsigned long long)jtr_ftell64(fp_eimg));
			a=(uint8_t)fgetc(fp_eimg);
			b=(uint8_t)fgetc(fp_eimg);
			if ((a != value_type[0]) || (b != value_type[1])) {
				fprintf(stderr, "Error: VMK not encrypted with AES-CCM (0x%x,0x%x)\n", a, b);
				found_ccm = 0;
			} else {
				fprintf(stderr, "VMK encrypted with AES-CCM!!\n");
				found_ccm = 1;
				ret = jtr_fseek64(fp_eimg, 3, SEEK_CUR);
				FRET_CHECK(ret)
			}

			if (found_ccm == 1)
				break;
			else if (y == 0) {
				ret = jtr_fseek64(fp_eimg, fp_before_aes, SEEK_SET);
				FRET_CHECK(ret)
			}
		}

		if (found_ccm == 1)
			break;
		else if (x == 0) {
			ret = jtr_fseek64(fp_eimg, fp_before_salt, SEEK_SET);
			FRET_CHECK(ret)
		}
	}

	return 0;
}


int process_encrypted_image(char *image_path)
{
	int64_t fileLen = 0, j = 0, ret;
	int version = 0, i = 0, match = 0;
	unsigned char c,d;

	fp_eimg = fopen(image_path, "r");
	if (!fp_eimg) {
		fprintf(stderr, "! %s : %s\n", image_path, strerror(errno));
		return 1;
	}

	ret = jtr_fseek64(fp_eimg, 0, SEEK_END);
	FRET_CHECK(ret)

	fileLen = jtr_ftell64(fp_eimg);
	FRET_CHECK(fileLen)
	printf("Encrypted device %s opened, size %lldMB\n", image_path, (long long)((fileLen/1024)/1024));
	ret = jtr_fseek64(fp_eimg, 0, SEEK_SET);
	FRET_CHECK(ret)

	for (j = 0; j < fileLen; j++) {
		for (i = 0; i < 8; i++) {
			c = fgetc(fp_eimg);
			if (c != signature[i])
				break;
		}
		if (i == 8) {
			match = 0x400; /* Search at least this many bytes for VMK entries */
			fprintf(stderr, "\nSignature found at 0x%llx\n", (unsigned long long)(jtr_ftell64(fp_eimg) - i));
			ret = jtr_fseek64(fp_eimg, 2, SEEK_CUR);
			version = fgetc(fp_eimg);
			fprintf(stderr, "Version: %d ", version);
			if (version == 1)
				fprintf(stderr, "(Windows Vista)\n");
			else if (version == 2)
				fprintf(stderr, "(Windows 7 or later)\n");
			else {
				fprintf(stderr, "\nInvalid version, looking for a signature with valid version...\n");
				match = 0;
			}
			continue;
		}
		if (match <= 0)
			continue;
		match -= i + 1;

		for (i = 0; i < 4; i++) {
			if (i) {
				c = fgetc(fp_eimg);
				match--;
			}
			if (c != vmk_entry[i])
				break;
		}

		if (i == 4) {
			fprintf(stderr, "\nVMK entry found at 0x%llx\n", (unsigned long long)(jtr_ftell64(fp_eimg) - i));
			ret = jtr_fseek64(fp_eimg, 28, SEEK_CUR);
			FRET_CHECK(ret)
			c = (unsigned char)fgetc(fp_eimg);
			d = (unsigned char)fgetc(fp_eimg);

			fp_before_salt = jtr_ftell64(fp_eimg);
			FRET_CHECK(fp_before_salt)

			if ((c == key_protection_clear[0]) && (d == key_protection_clear[1]))
				fprintf(stderr, "VMK not encrypted.. stored clear! (0x%llx)\n", (unsigned long long)fp_before_salt);
			else if ((c == key_protection_tpm[0]) && (d == key_protection_tpm[1]))
				fprintf(stderr, "VMK encrypted with TPM...not supported! (0x%llx)\n", (unsigned long long)fp_before_salt);
			else if ((c == key_protection_start_key[0]) && (d == key_protection_start_key[1]))
				fprintf(stderr, "VMK encrypted with Startup Key...not supported! (0x%llx)\n", (unsigned long long)fp_before_salt);
			else if ((c == key_protection_recovery[0]) && (d == key_protection_recovery[1]) && recoveryPasswordFound == 0) {
				fprintf(stderr, "\nVMK encrypted with Recovery Password found at 0x%llx\n", (unsigned long long)fp_before_salt);
				rp_search_salt_aes();
				if (found_ccm == 0)
					continue;

				fillBuffer(fp_eimg, r_nonce, NONCE_SIZE);
				fprintf(stdout, "RP Nonce: ");
				print_hex(r_nonce, NONCE_SIZE, stdout);

				fillBuffer(fp_eimg, r_mac, MAC_SIZE);
				fprintf(stdout, "\nRP MAC: ");
				print_hex(r_mac, MAC_SIZE, stdout);

				fprintf(stdout, "\nRP VMK: ");
				fillBuffer(fp_eimg, r_vmk, VMK_SIZE);
				print_hex(r_vmk, VMK_SIZE, stdout);
				fprintf(stdout, "\n\n");
				fflush(stdout);
				recoveryPasswordFound = 1;
				if (userPasswordFound)
					break;
			}
			else if ((c == key_protection_password[0]) && (d == key_protection_password[1]) && userPasswordFound == 0) {
				fprintf(stderr, "\nVMK encrypted with User Password found at %llx\n", (long long)fp_before_salt);
				ret = fseek(fp_eimg, 12, SEEK_CUR);
				FRET_CHECK(ret)
				fillBuffer(fp_eimg, p_salt, SALT_SIZE);
				ret = fseek(fp_eimg, 83, SEEK_CUR);
				FRET_CHECK(ret)
				if (((unsigned char)fgetc(fp_eimg) != value_type[0]) || ((unsigned char)fgetc(fp_eimg) != value_type[1])) {
					fprintf(stderr, "Error: VMK not encrypted with AES-CCM\n");
					continue;
				} else
					fprintf(stderr, "VMK encrypted with AES-CCM\n");

				ret = fseek(fp_eimg, 3, SEEK_CUR);
				FRET_CHECK(ret)

				fillBuffer(fp_eimg, p_nonce, NONCE_SIZE);
				fprintf(stdout, "UP Nonce: ");
				print_hex(p_nonce, NONCE_SIZE, stdout);

				fillBuffer(fp_eimg, p_mac, MAC_SIZE);
				fprintf(stdout, "\nUP MAC: ");
				print_hex(p_mac, MAC_SIZE, stdout);

				fillBuffer(fp_eimg, p_vmk, VMK_SIZE);
				fprintf(stdout, "\nUP VMK: ");
				print_hex(p_vmk, VMK_SIZE, stdout);
				fprintf(stdout, "\n\n");
				fflush(stdout);
				userPasswordFound = 1;
				if (recoveryPasswordFound)
					break;
			}
		}
	}

	fclose(fp_eimg);

	if (userPasswordFound == 0 && recoveryPasswordFound == 0) {
#ifndef HAVE_LIBFUZZER
		fprintf(stderr, "Error while extracting data: No signature found!\n");
		return 1;
#endif
	} else {
		if (userPasswordFound == 1) {
			// UP
			printf("\nUser Password hash:\n");
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

		if (recoveryPasswordFound == 1) {
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
				image_path = xstrdup(optarg);
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

	return 0;
}

#endif  // HAVE_LIBFUZZER

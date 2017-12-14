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
 * More info here: http://openwall.info/wiki/john/OpenCL-BitLocker
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

#define HASH_UP 	0
#define HASH_UP_MAC	1
#define HASH_RP 	2
#define HASH_RP_MAC	3

#define INPUT_SIZE 1024
#define SALT_SIZE 16
#define MAC_SIZE 16
#define NONCE_SIZE 12
#define IV_SIZE 16
#define VMK_SIZE 44
#define SIGNATURE_LEN 9

//Attack User Password mode
#define FILE_OUT_HASH_USER "hash_user_pass.txt"
//Attack User Password mode with MAC verification
#define FILE_OUT_HASH_USER_MAC "hash_user_pass_mac.txt"
//Attack Recovery Password
#define FILE_OUT_HASH_RECV "hash_recv_pass.txt"
//Attack Recovery Password mode with MAC verification
#define FILE_OUT_HASH_RECV_MAC "hash_recv_pass_mac.txt"

static unsigned char p_salt[SALT_SIZE], p_nonce[NONCE_SIZE], p_mac[MAC_SIZE], p_vmk[VMK_SIZE];
static unsigned char r_salt[SALT_SIZE], r_nonce[NONCE_SIZE], r_mac[MAC_SIZE], r_vmk[VMK_SIZE];
static char * imagePath=NULL;
static char * outHashUser=NULL;
static char * outHashUserMac=NULL;
static char * outHashRecovery=NULL;
static char * outHashRecoveryMac=NULL;

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

int process_encrypted_image()
{
	int version = 0, fileLen = 0, j = 0, i = 0, match = 0, vmkFound=0, recoveryFound=0;
	const char signature[SIGNATURE_LEN] = "-FVE-FS-";
	unsigned char vmk_entry[4] = { 0x02, 0x00, 0x08, 0x00 };
	unsigned char key_protection_clear[2] = { 0x00, 0x00 };
	unsigned char key_protection_tpm[2] = { 0x00, 0x01 };
	unsigned char key_protection_start_key[2] = { 0x00, 0x02 };
	unsigned char key_protection_recovery[2] = { 0x00, 0x08 };
	unsigned char key_protection_password[2] = { 0x00, 0x20 };
	unsigned char value_type[2] = { 0x00, 0x05 };
	char a,b,c,d;
	FILE *outFileUser, *outFileUserMac, *outFileRecv, *outFileRecvMac, *encryptedImage;

	printf("Opening file %s\n", imagePath);
	encryptedImage = fopen(imagePath, "r");

	if (!encryptedImage || !outHashUser || !outHashRecovery) {
		fprintf(stderr, "! %s : %s\n", imagePath, strerror(errno));
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
		if(match == 0) { i=0; continue; }

		i = 0;
		while (i < 4 && (unsigned char)c == vmk_entry[i]) {
			c = fgetc(encryptedImage);
			i++;
		}

		if (i == 4) {
			fprintf(stderr, "\nVMK entry found at 0x%08lx\n", (ftell(encryptedImage) - i - 3));
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
			{
				fprintf(stderr, "VMK encrypted with Recovery key found!\n");
				fseek(encryptedImage, 12, SEEK_CUR);
				fillBuffer(encryptedImage, r_salt, SALT_SIZE);
				fseek(encryptedImage, 147, SEEK_CUR);
				a=(unsigned char)fgetc(encryptedImage);
				b=(unsigned char)fgetc(encryptedImage);
				if (( a != value_type[0]) || (b != value_type[1])) {
					fprintf(stderr, "Error: VMK not encrypted with AES-CCM, a: %02x, b: %02x\n",a ,b);
					match=0;
					i=0;
					continue;
				}
				else fprintf(stderr, "VMK encrypted with AES-CCM\n");

				fseek(encryptedImage, 3, SEEK_CUR);
				fillBuffer(encryptedImage, r_nonce, NONCE_SIZE);
				fillBuffer(encryptedImage, r_mac, MAC_SIZE);
				fillBuffer(encryptedImage, r_vmk, VMK_SIZE);
				recoveryFound=1;
			}
			else if ((c == key_protection_password[0]) && (d == key_protection_password[1]) && vmkFound == 0) 
			{
				fprintf(stderr, "VMK encrypted with user password found!\n");
				fseek(encryptedImage, 12, SEEK_CUR);
				fillBuffer(encryptedImage, p_salt, SALT_SIZE);
				fseek(encryptedImage, 83, SEEK_CUR);
				if (((unsigned char)fgetc(encryptedImage) != value_type[0]) || ((unsigned char)fgetc(encryptedImage) != value_type[1])) {
					fprintf(stderr, "Error: VMK not encrypted with AES-CCM\n");
					match=0;
					i=0;
					continue;
				}
				else fprintf(stderr, "VMK encrypted with AES-CCM\n");

				fseek(encryptedImage, 3, SEEK_CUR);
				fillBuffer(encryptedImage, p_nonce, NONCE_SIZE);
				fillBuffer(encryptedImage, p_mac, MAC_SIZE);
				fillBuffer(encryptedImage, p_vmk, VMK_SIZE);
				vmkFound=1;
			}
		}

		i = 0;
		if(vmkFound == 1 && recoveryFound == 1) break;
	}

	fclose(encryptedImage);

	if (vmkFound == 0 && recoveryFound == 0) {
#ifndef HAVE_LIBFUZZER
		fprintf(stderr, "Error while extracting data: No signature found!\n");
		return 1;
#endif
	} else {
		if(vmkFound == 1)
		{
#if 0
			printf("\nUser Password hash:\n$bitlocker$%d$%d$", HASH_UP, SALT_SIZE);
			print_hex(p_salt, SALT_SIZE, stdout);
			printf("$%d$%d$", 0x100000, NONCE_SIZE); // fixed iterations , fixed nonce size
			print_hex(p_nonce, NONCE_SIZE, stdout);
			printf("$%d$", VMK_SIZE + MAC_SIZE);
			print_hex(p_mac, MAC_SIZE, stdout); // hack, this should actually be entire AES-CCM encrypted block (which includes vmk)
			print_hex(p_vmk, VMK_SIZE, stdout);
			printf("\n");
#endif
			//UP
			outFileUser = fopen(outHashUser, "w");
			if (!outFileUser) {
				fprintf(stderr, "Error creating ./%s : %s\n", outHashUser, strerror(errno));
				return 1;
			}

			fprintf(outFileUser, "$bitlocker$%d$%d$", HASH_UP, SALT_SIZE);
			print_hex(p_salt, SALT_SIZE, outFileUser);
			fprintf(outFileUser, "$%d$%d$", 0x100000, NONCE_SIZE); // fixed iterations , fixed nonce size
			print_hex(p_nonce, NONCE_SIZE, outFileUser);
			fprintf(outFileUser, "$%d$", VMK_SIZE + MAC_SIZE);
			print_hex(p_mac, MAC_SIZE, outFileUser); 
			print_hex(p_vmk, VMK_SIZE, outFileUser);
			fprintf(outFileUser, "\n");

			fclose(outFileUser);

			//UP with MAC
			outFileUserMac = fopen(outHashUserMac, "w");
			if (!outFileUserMac) {
				fprintf(stderr, "Error creating ./%s : %s\n", outHashUserMac, strerror(errno));
				return 1;
			}

			fprintf(outFileUserMac, "$bitlocker$%d$%d$", HASH_UP_MAC, SALT_SIZE);
			print_hex(p_salt, SALT_SIZE, outFileUserMac);
			fprintf(outFileUserMac, "$%d$%d$", 0x100000, NONCE_SIZE); // fixed iterations , fixed nonce size
			print_hex(p_nonce, NONCE_SIZE, outFileUserMac);
			fprintf(outFileUserMac, "$%d$", VMK_SIZE + MAC_SIZE);
			print_hex(p_mac, MAC_SIZE, outFileUserMac); 
			print_hex(p_vmk, VMK_SIZE, outFileUserMac);
			fprintf(outFileUserMac, "\n");

			fclose(outFileUserMac);

		}

		if(recoveryFound == 1)
		{
#if 0
			printf("\nRecovery Key hash:\n$bitlocker$%d$%d$", HASH_RP, SALT_SIZE);
			print_hex(r_salt, SALT_SIZE, stdout);
			printf("$%d$%d$", 0x100000, NONCE_SIZE); // fixed iterations , fixed nonce size
			print_hex(r_nonce, NONCE_SIZE, stdout);
			printf("$%d$", VMK_SIZE + MAC_SIZE);
			print_hex(r_mac, MAC_SIZE, stdout); // hack, this should actually be entire AES-CCM encrypted block (which includes vmk)
			print_hex(r_vmk, VMK_SIZE, stdout);
			printf("\n");
#endif
			//RP
			outFileRecv = fopen(outHashRecovery, "w");
			if (!outFileRecv) {
				fprintf(stderr, "Error creating ./%s : %s\n", outHashRecovery, strerror(errno));
				return 1;
			}

			fprintf(outFileRecv, "$bitlocker$%d$%d$", HASH_RP, SALT_SIZE);
			print_hex(r_salt, SALT_SIZE, outFileRecv);
			fprintf(outFileRecv, "$%d$%d$", 0x100000, NONCE_SIZE); // fixed iterations , fixed nonce size
			print_hex(r_nonce, NONCE_SIZE, outFileRecv);
			fprintf(outFileRecv, "$%d$", VMK_SIZE + MAC_SIZE);
			print_hex(r_mac, MAC_SIZE, outFileRecv); 
			print_hex(r_vmk, VMK_SIZE, outFileRecv);
			fprintf(outFileRecv, "\n");
			
			fclose(outFileRecv);

			//RP with MAC
			outFileRecvMac = fopen(outHashRecoveryMac, "w");
			if (!outFileRecvMac) {
				fprintf(stderr, "Error creating ./%s : %s\n", outHashRecoveryMac, strerror(errno));
				return 1;
			}

			fprintf(outFileRecvMac, "$bitlocker$%d$%d$", HASH_RP_MAC, SALT_SIZE);
			print_hex(r_salt, SALT_SIZE, outFileRecvMac);
			fprintf(outFileRecvMac, "$%d$%d$", 0x100000, NONCE_SIZE); // fixed iterations , fixed nonce size
			print_hex(r_nonce, NONCE_SIZE, outFileRecvMac);
			fprintf(outFileRecvMac, "$%d$", VMK_SIZE + MAC_SIZE);
			print_hex(r_mac, MAC_SIZE, outFileRecvMac); 
			print_hex(r_vmk, VMK_SIZE, outFileRecvMac);
			fprintf(outFileRecvMac, "\n");
			
			fclose(outFileRecvMac);

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
	process_encrypted_image();
	remove(name);

	return 0;
}
#else

static int usage(char *name){
	printf("\nUsage: %s -i <Image of encrypted memory unit> -o <output files path>\n\n"
		"Options:\n\n"
		"  -h"
		"\t\tShow this help\n"
		"  -i"
		"\t\tImage path of encrypted memory unit encrypted with BitLocker\n"
		"  -o"
		"\t\tOutputs path (i.e. /some/path/for/outputs/). Default: current directory\n\n", name);

	return EXIT_FAILURE;
}

int main(int argc, char **argv)
{
	int opt;
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
				if(strlen(optarg) >= INPUT_SIZE)
				{
					fprintf(stderr, "ERROR: Input string is bigger than %d\n", INPUT_SIZE);
					exit(EXIT_FAILURE);
				}
				imagePath=(char *)Calloc(INPUT_SIZE, sizeof(char));
				strncpy(imagePath, optarg, strlen(optarg)+1);
				break;

			case 'o':
				if(strlen(optarg) >= INPUT_SIZE)
				{
					fprintf(stderr, "ERROR: Input string is bigger than %d\n", INPUT_SIZE);
					exit(EXIT_FAILURE);
				}
				outHashUser = (char*)Calloc( (strlen(optarg)+strlen(FILE_OUT_HASH_USER)+2), sizeof(char));
				memcpy(outHashUser, optarg, strlen(optarg));
				outHashUser[strlen(optarg)] = '/';
				memcpy(outHashUser+strlen(optarg)+1, FILE_OUT_HASH_USER, strlen(FILE_OUT_HASH_USER));

				outHashUserMac = (char*)Calloc( (strlen(optarg)+strlen(FILE_OUT_HASH_USER_MAC)+2), sizeof(char));
				memcpy(outHashUserMac, optarg, strlen(optarg));
				outHashUserMac[strlen(optarg)] = '/';
				memcpy(outHashUserMac+strlen(optarg)+1, FILE_OUT_HASH_USER_MAC, strlen(FILE_OUT_HASH_USER_MAC));

				outHashRecovery = (char*)Calloc( (strlen(optarg)+strlen(FILE_OUT_HASH_RECV)+2), sizeof(char));
				memcpy(outHashRecovery, optarg, strlen(optarg));
				outHashRecovery[strlen(optarg)] = '/';
				memcpy(outHashRecovery+strlen(optarg)+1, FILE_OUT_HASH_RECV, strlen(FILE_OUT_HASH_RECV));

				outHashRecoveryMac = (char*)Calloc( (strlen(optarg)+strlen(FILE_OUT_HASH_RECV_MAC)+2), sizeof(char));
				memcpy(outHashRecoveryMac, optarg, strlen(optarg));
				outHashRecoveryMac[strlen(optarg)] = '/';
				memcpy(outHashRecoveryMac+strlen(optarg)+1, FILE_OUT_HASH_RECV_MAC, strlen(FILE_OUT_HASH_RECV_MAC));
				
				break;

			default:
				break;
		}
	}

	if(!imagePath)
	{
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	
	if(outHashUser == NULL) //Current directory
	{
		outHashUser = (char*)Calloc( (strlen(FILE_OUT_HASH_USER)+1), sizeof(char));
		memcpy(outHashUser, FILE_OUT_HASH_USER, strlen(FILE_OUT_HASH_USER));
	}

	if(outHashRecovery == NULL) //Current directory
	{
		outHashRecovery = (char*)Calloc( (strlen(FILE_OUT_HASH_RECV)+1), sizeof(char));
		memcpy(outHashRecovery, FILE_OUT_HASH_RECV, strlen(FILE_OUT_HASH_RECV));
	}

	printf("\n---------> bitlocker2john hash extractor <---------\n");
	if(process_encrypted_image())
		fprintf(stderr, "\nError while parsing input device image\n");
	else
		printf("\nOutput files:\nUser Password:\"%s\"\nUser Password with MAC:\"%s\"\nRecovery Password:\"%s\"\nRecovery Password with MAC:\"%s\"\n", outHashUser, outHashUserMac, outHashRecovery, outHashRecoveryMac);

	free(outHashUser);
	free(outHashUserMac);
	free(outHashRecovery);
	free(outHashRecoveryMac);
	
	MEMDBG_PROGRAM_EXIT_CHECKS(stderr);

	return 0;
}

#endif  // HAVE_LIBFUZZER

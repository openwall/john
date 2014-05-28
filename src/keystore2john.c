/*
 * Output password protected Java KeyStore files in JtR
 * compatible format.
 *
 * Output Format: $keystore$target$data_length$data$hash$nkeys$keylength$keydata$keylength$keydata...
 *
 * Where,
 *
 * target == 0 if container password is to be cracked
 * target == 1 if private key password(s) are to be cracked
 *
 * TODO:
 *
 * 1. Private Keys can be encrypted with a password different from the container password.
 * Add support for cracking such keys.
 *
 * 2. Add ability to select any key for cracking in case multiple keys are present.
 */

/*
 * KEYSTORE FORMAT:
 *
 * Magic number (big-endian integer),
 * Version of this file format (big-endian integer),
 *
 * Count (big-endian integer),
 * followed by "count" instances of either:
 *
 *     {
 *      tag=1 (big-endian integer),
 *      alias (UTF string)
 *      timestamp
 *      encrypted private-key info according to PKCS #8
 *          (integer length followed by encoding)
 *      cert chain (integer count, then certs; for each cert,
 *          integer length followed by encoding)
 *     }
 *
 * or:
 *
 *     {
 *      tag=2 (big-endian integer)
 *      alias (UTF string)
 *      timestamp
 *      cert (integer length followed by encoding)
 *     }
 *
 * ended by a keyed SHA1 hash (bytes only) of
 *     { password + whitener + preceding body }
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "stdint.h"
#include "jumbo.h"
#include "memdbg.h"

#define N 819200

static int MAGIC = 0xfeedfeed;
static int VERSION_1 = 0x01;
static int VERSION_2 = 0x02;

static unsigned char data[N];
static unsigned char protectedPrivKey[N];
static unsigned char certdata[N];
static unsigned char buf[N];

static uint32_t fget32(FILE * fp)
{
        uint32_t v = fgetc(fp) << 24;
        v |= fgetc(fp) << 16;
        v |= fgetc(fp) << 8;
        v |= fgetc(fp);
        return v;
}

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}

static void process_file(char *filename)
{
	FILE *fp;
	int i, j;
	int tag;
	unsigned char p, length;
	int count, keysize = 0;
	int numOfCerts, certsize;
	long size;
	size_t read;
	int pos;
	unsigned char md[20];
	int xMagic;
	int xVersion;
	char *bname;
	const char *extension[] = { ".keystore" };

	if (!(fp = fopen(filename, "rb"))) {
		fprintf(stderr, "! %s: %s\n", filename, strerror(errno));
		goto bail;
	}
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	assert(size <= sizeof(data));
	fseek(fp, 0, SEEK_SET);
	read = fread(data, size, 1,  fp);
	assert(read == 1);
	fseek(fp, 0, SEEK_SET);

	xMagic = fget32(fp);
	xVersion = fget32(fp);

	if (xMagic!=MAGIC || (xVersion!=VERSION_1 && xVersion!=VERSION_2)) {
		fprintf(stderr, "Invalid keystore format\n");
		goto bail;
	}

	count = fget32(fp);
	for (i = 0; i < count; i++) {
			tag = fget32(fp);

		if (tag == 1) { // key entry
			// Read the alias
			p = fgetc(fp);
			length = fgetc(fp);
			read = fread(buf, length, 1, fp);
			assert(read == 1);

			// Read the (entry creation) date
			read = fread(buf, 8, 1, fp);
			assert(read == 1);

			// Read the key
			keysize = fget32(fp);
			read = fread(protectedPrivKey, keysize, 1, fp);
			assert(read == 1);

			// read certificates
			numOfCerts = fget32(fp);
			if (numOfCerts > 0) {
				for (j = 0; j < numOfCerts; j++) {
					if (xVersion == 2) {
						// read the certificate type
						p = fgetc(fp);
						assert(p == 1 || p == 0);
						length = fgetc(fp);
						read = fread(buf, length, 1, fp);
						assert(read == 1);
					}
					// read certificate data
					certsize = fget32(fp);
					read = fread(certdata, certsize, 1, fp);
					assert(read == 1);
				}
			}
			// We can be sure now that numOfCerts of certs are read
		} else if (tag == 2) { // trusted certificate entry
			// Read the alias
			p = fgetc(fp);
			length = fgetc(fp);
			read = fread(buf, length, 1, fp);
			assert(read == 1);

			// Read the (entry creation) date
			read = fread(buf, 8, 1, fp);
			assert(read == 1);

			// Read the trusted certificate
			if (xVersion == 2) {
				// read the certificate type
				p = fgetc(fp);
				length = fgetc(fp);
				read = fread(buf, length, 1, fp);
				assert(read == 1);
			}
			certsize = fget32(fp);
			read = fread(certdata, certsize, 1, fp);
			assert(read == 1);

		} else {
			fprintf(stderr, "Unrecognized keystore entry");
			fclose(fp);
			goto bail;
		}
	}

	/* how much data have we processed */
	pos = ftell(fp);

	/* read hash */
	read = fread(md, 20, 1, fp);
	assert(read == 1);

	bname = strip_suffixes(basename(filename), extension, 1);
	printf("%s:$keystore$0$%d$", bname, pos);
	print_hex(data, pos);
	printf("$");
	print_hex(md, 20);
	printf("$%d$%d$", count, keysize);
	print_hex(protectedPrivKey, keysize);
	printf(":::::%s\n", filename);
bail:
	return;
}

int keystore2john(int argc, char **argv)
{
        if (argc < 2) {
                fprintf(stderr, "Usage: %s <.keystore file>\n", argv[0]);
                exit(-1);
        }
        process_file(argv[1]);
	MEMDBG_PROGRAM_EXIT_CHECKS(stderr);
	return 0;
}

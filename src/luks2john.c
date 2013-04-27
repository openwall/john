/* luks.c
 *
 * hashkill - a hash cracking tool
 * Copyright (C) 2010 Milen Rangelov <gat3way@gat3way.eu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <alloca.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <arpa/inet.h>

#define LUKS_MAGIC_L        6
#define LUKS_CIPHERNAME_L   32
#define LUKS_CIPHERMODE_L   32
#define LUKS_HASHSPEC_L     32
#define UUID_STRING_L       40
#define LUKS_DIGESTSIZE 20
#define LUKS_SALTSIZE 32
#define LUKS_NUMKEYS 8

/* taken from LUKS on disk format specification */
struct luks_phdr {
	char magic[LUKS_MAGIC_L];
	uint16_t version;
	char cipherName[LUKS_CIPHERNAME_L];
	char cipherMode[LUKS_CIPHERMODE_L];
	char hashSpec[LUKS_HASHSPEC_L];
	uint32_t payloadOffset;
	uint32_t keyBytes;
	char mkDigest[LUKS_DIGESTSIZE];
	char mkDigestSalt[LUKS_SALTSIZE];
	uint32_t mkDigestIterations;
	char uuid[UUID_STRING_L];
	struct {
		uint32_t active;
		uint32_t passwordIterations;
		char passwordSalt[LUKS_SALTSIZE];
		uint32_t keyMaterialOffset;
		uint32_t stripes;
	} keyblock[LUKS_NUMKEYS];
} myphdr;


static unsigned char *cipherbuf;
static int afsize;
static unsigned int bestslot = 2000;


static int af_sectors(int blocksize, int blocknumbers)
{
	int af_size;

	af_size = blocksize * blocknumbers;
	af_size = (af_size + 511) / 512;
	af_size *= 512;
	return af_size;
}

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}

static int hash_plugin_parse_hash(char *filename)
{
	FILE *myfile;
	int cnt;
	int readbytes;
	unsigned int bestiter = 0xFFFFFFFF;

	myfile = fopen(filename, "rb");

	if (fread(&myphdr, sizeof(struct luks_phdr), 1, myfile) < 1) {
		fprintf(stderr, "%s : file opening problem!", filename);
		return -1;
	}

	if (strcmp(myphdr.magic, "LUKS\xba\xbe") != 0) {
		fprintf(stderr, "%s : not a LUKS file / disk", filename);
		return -2;
	}

	if (strcmp(myphdr.cipherName, "aes") != 0) {
		fprintf(stderr, "%s : Only AES cipher supported. Used cipher: %s\n",
			filename, myphdr.cipherName);
	}

	for (cnt = 0; cnt < LUKS_NUMKEYS; cnt++) {
		if ((ntohl(myphdr.keyblock[cnt].passwordIterations) < bestiter)
		    && (ntohl(myphdr.keyblock[cnt].passwordIterations) > 1) &&
		    (ntohl(myphdr.keyblock[cnt].active) == 0x00ac71f3)) {
			bestslot = cnt;
			bestiter =
			    ntohl(myphdr.keyblock[cnt].passwordIterations);
		}
	}
	if (bestslot == 2000)
		goto bad;

	afsize =
	    af_sectors(ntohl(myphdr.keyBytes),
	    ntohl(myphdr.keyblock[bestslot].stripes));
	cipherbuf = malloc(afsize);
	fseek(myfile, ntohl(myphdr.keyblock[bestslot].keyMaterialOffset) * 512,
	    SEEK_SET);
	readbytes = fread(cipherbuf, afsize, 1, myfile);

	if (readbytes < 0) {
		free(cipherbuf);
		fclose(myfile);
		goto bad;
	}
	fprintf(stderr, "Best keyslot [%d]: %d keyslot iterations, %d stripes, %d mkiterations\n", bestslot, ntohl(myphdr.keyblock[bestslot].passwordIterations),ntohl(myphdr.keyblock[bestslot].stripes),ntohl(myphdr.mkDigestIterations));
	printf("$luks$%s$", filename);
	print_hex((unsigned char *)myphdr.mkDigest, LUKS_DIGESTSIZE);
	printf("\n");

	return 0;
bad:
	printf("%s : parsing failed\n", filename);
	return 1;
}


int main(int argc, char **argv)
{
	int i;

	if (argc < 2) {
		puts("Usage: luks2john [LUKS files / disks]");
		return -1;
	}
	for (i = 1; i < argc; i++)
		hash_plugin_parse_hash(argv[i]);

	return 0;
}

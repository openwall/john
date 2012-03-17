/* VNC password decoder
 * gcc -Wall vnc-decoder.c d3des.c -o vnc-decoder */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include "d3des.h"

static unsigned char fixedkey[8] = {23,82,107,6,35,78,88,7};

/* char2hex is borrowed from VNC Password Dumper
 * Copyright (c) 2006- Patrik Karlsson
 * http://www.cqure.net, LICENSE: GPL
 * http://www.gnu.org/licenses/gpl-2.0.html */
unsigned char *char2hex(char *chr, int nLen)
{
	int i;
	unsigned char hex[2];
	unsigned char *retHex;
	unsigned int hex3;

	retHex = (unsigned char *)malloc(nLen);
	memset(retHex, 0, nLen);

	for ( i=0; i<nLen; i++ ) {
		memset(hex, 0, sizeof( hex ) );
		memcpy(hex, chr + i, 2 );
		sscanf((char*)hex, "%2x", &hex3);
		retHex[i/2] = hex3;
		i++;
	}
	return retHex;
}

static void decrypt_epw(unsigned char *epw)
{
	unsigned char pt[9];
	deskey(fixedkey, DE1);
	des(epw, pt);
	pt[8] = 0;
	printf("Password: %s\n", pt);
}

static void process_file(const char *filename)
{
	FILE *fp;
	unsigned char buffer[16];
	int count;

	if (!(fp = fopen(filename, "rb"))) {
		fprintf(stderr, "! %s : %s\n", filename, strerror(errno));
		return;
	}
	count = fread(buffer, 8, 1, fp);
	assert(count == 1);
	decrypt_epw(buffer);
	fclose(fp);
}

static void usage(char **argv)
{
	printf(
			"Usage: %s [OPTIONS]\n\n"
			"Options:\n"
			"       -f <VNC passwd file> = use VNC passwd file\n"
			"       -s <VNC Encrypted Password in HEX> = use encrypted password hex string\n", argv[0]);
}



int main( int argc, char **argv )
{
	if(argc < 2) {
		usage(argv);
		exit(-1);
	}
	int fflag = 0;
	int sflag = 0;
	char *filename = NULL;
	char *epw = NULL;
	int index;
	int c;

	opterr = 0;
	while((c = getopt(argc, argv, "f:s:")) != -1)
		switch (c)
		{
			case 'f':
				fflag = 1;
				filename = optarg;
				break;
			case 's':
				sflag = 1;
				epw = optarg;
				break;
				break;
			case '?':
				if(optopt == 'f') {
					fprintf (stderr, "Option -%c requires an argument.\n\n", optopt);
					usage(argv);
				}
				else if(optopt == 's') {
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
					usage(argv);
				}
				else if(optopt) {
					fprintf (stderr, "Unknown option requested\n\n");
					usage(argv);
				}
				return 1;
			default:
				abort();
		}

	if(sflag) {
		unsigned char *ct = char2hex(epw, 16);
		decrypt_epw(ct);
		free(ct);
	}
	else if(fflag)
		process_file(filename);

	return 0;
}

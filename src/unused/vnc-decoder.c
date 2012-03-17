/* VNC password decoder
 * gcc -Wall vnc-decoder.c d3des.c -o vnc-decoder */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
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

void decrypt_epw(char *epw)
{
	unsigned char pt[9];
	unsigned char *ct = char2hex(epw, 16);
	deskey(fixedkey, DE1);
	des(ct, pt);
	pt[8] = 0;
	printf("Password: %s\n", pt);
}

int main( int argc, char **argv )
{
	if(argc < 2) {
		fprintf(stderr, "Usage: %s <VNC Encrypted Password in HEX>\n", argv[0]);
		exit(-1);
	}

	decrypt_epw(argv[1]);

	return 0;
}

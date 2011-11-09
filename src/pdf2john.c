 /**
 * Copyright (C) 2006 Henning Norén
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 *
 * Re-factored for JtR by Dhiru Kholia during June, 2011 for GSoC.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

#include "pdfparser.h"
#include "pdfcrack.h"
#include "stdint.h"

#define VERSION_MAJOR 0
#define VERSION_MINOR 11

/* print some help for the user */
static void printHelp(char *progname)
{
	printf("Usage: %s [OPTIONS] filename\n"
	    "OPTIONS:\n"
	    "-o, --owner\t\tWork with the ownerpassword (default is userpassword)\n"
	    "-p, --password=STRING\tGive userpassword to speed up breaking\n"
	    "\t\t\townerpassword (implies -o)\n"
	    "-v, --version\t\tPrint version and exit\n", progname);
}

int pdf2john(int argc, char **argv)
{
	int ret = 0;
	FILE *file = NULL;
	uint8_t *userpassword = NULL;
	char *inputfile = NULL;
	unsigned char *p;
	EncData *e = calloc(1, sizeof(EncData));
	e->work_with_user = true;

	/* parse arguments */
	while (true) {
		int c;
		c = getopt(argc, argv, "op:v");
		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 'o':
			e->work_with_user = false;
			break;
		case 'p':
			userpassword = (uint8_t *) strdup(optarg);
			e->work_with_user = false;
			e->have_userpassword = true;
			break;
		case 'v':
			printf("pdfcrack version %d.%d\n", VERSION_MAJOR,
			    VERSION_MINOR);
			return 0;
		default:
			printHelp(argv[0]);
			ret = 1;
		}
	}
	int i = optind;
	if (i > 0) {
		if (i < argc)
			inputfile = strdup(argv[i++]);
	}

	if (!inputfile) {
		printHelp(argv[0]);
		ret = 1;
		goto cleanup;
	}

	if ((file = fopen(inputfile, "r")) == 0) {
		fprintf(stderr, "Error: file %s not found\n", inputfile);
		ret = 2;
		goto cleanup;
	}

	if (!openPDF(file, e)) {
		fprintf(stderr, "Error: Not a valid PDF\n");
		ret = 3;
		goto cleanup;
	}

	ret = getEncryptedInfo(file, e);
	if (ret) {
		if (ret == EENCNF)
			fprintf(stderr,
			    "Error: Could not extract encryption information\n");
		else if (ret == ETRANF || ret == ETRENF || ret == ETRINF)
			fprintf(stderr,
			    "Error: Encryption not detected (is the document password protected?)\n");
		ret = 4;
		goto cleanup;
	} else if (e->revision < 2 || (strcmp(e->s_handler, "Standard") != 0)) {
		fprintf(stderr,
		    "The specific version is not supported (%s - %d)\n",
		    e->s_handler, e->revision);
		ret = 5;
		goto cleanup;
	}

	if (fclose(file)) {
		fprintf(stderr, "Error: closing file %s\n", inputfile);
	}
#ifdef UNPDF_DEBUG
	printEncData(e);
#endif
    /* try to initialize the cracking-engine */
    if (!initPDFCrack(e, userpassword, e->work_with_user)) {
        cleanPDFCrack();
        fprintf(stderr, "Wrong userpassword given, '%s'\n", userpassword);
        exit(-1);
    }

	/* deep serialize "e" structure */
	printf("%s:$pdf$%s*", inputfile, e->s_handler);
	p = e->o_string;
	for (i = 0; i < 32; i++)
		printf("%c%c", itoa16[ARCH_INDEX(p[i] >> 4)],
		    itoa16[ARCH_INDEX(p[i] & 0x0f)]);
	printf("*");
	p = e->u_string;
	for (i = 0; i < 32; i++)
		printf("%c%c",
		    itoa16[ARCH_INDEX(p[i] >> 4)],
		    itoa16[ARCH_INDEX(p[i] & 0x0f)]);
	printf("*%d*", e->fileIDLen);
	p = e->fileID;
	for (i = 0; i < e->fileIDLen; i++)
		printf("%c%c",
		    itoa16[ARCH_INDEX(p[i] >> 4)],
		    itoa16[ARCH_INDEX(p[i] & 0x0f)]);
	printf("*%d*%d*%d*%u*%u*%d*%d*%d*%d", e->encryptMetaData,
	    e->work_with_user, e->have_userpassword, e->version_major,
	    e->version_minor, e->length, e->permissions, e->revision,
	    e->version);
	if (e->have_userpassword)
		printf("*%s\n", userpassword);
	else
		printf("\n");

	exit(0);

cleanup:

	return ret;
}

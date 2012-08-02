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
#ifndef _MSC_VER
#include <unistd.h>
#endif
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

#ifdef _MSC_VER
// Horrible getopt, but 'good enough' to get VC working to help ease debugging.
// WOrked for me (JimF). If not good enough for some otehr VC user, then fix it ;)
char *optarg;
int optind = 1;
int getopt(int argc, char **argv, char *ignore) {
	static int arg = 1;
	char *cp, ret;
	if (optind == argc) return -1;
	cp = argv[optind];
	if (*cp == '-') ++cp;
	if (*cp == '-') ++cp;
	ret = *cp;
	if (*cp == 'p') {
		if (!strncmp(cp, "password=", 9)) {
			optarg = &cp[9];
		} else {
			optarg = argv[++optind];
		}
	}
	if (ret != 'v' && ret != 'o' && ret != 'v')
		return -1;
	++optind;
	return ret;
}
#endif

int pdf2john(int argc, char **argv)
{
	int ret = 0;
	int c, i;
	FILE *file = NULL;
	uint8_t *userpassword = NULL;
	char *inputfile = NULL;
	unsigned char *p;
	struct custom_salt cs;

	// cs MUST be memset, or later pointer checks are used against random stack memory (i.e. uninitialze pointers)
	memset(&cs, 0, sizeof(cs));
	cs.e.work_with_user = true;
	cs.e.have_userpassword = false;

	/* parse arguments */
	while (true) {
		c = getopt(argc, argv, "op:v");
		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 'o':
			cs.e.work_with_user = false;
			break;
		case 'p':
			userpassword = (uint8_t *) strdup(optarg);
			cs.e.work_with_user = false;
			cs.e.have_userpassword = true;
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
	i = optind;
	if (i > 0) {
		if (i < argc)
			inputfile = strdup(argv[i++]);
	}

	if (!inputfile) {
		printHelp(argv[0]);
		ret = 1;
		goto cleanup;
	}

	if ((file = fopen(inputfile, "rb")) == NULL) {
		fprintf(stderr, "Error: file %s not found\n", inputfile);
		ret = 2;
		goto cleanup;
	}

	if (!openPDF(file, &cs.e)) {
		fprintf(stderr, "Error: Not a valid PDF\n");
		ret = 3;
		goto cleanup;
	}

	ret = getEncryptedInfo(file, &cs.e);
	if (ret) {
		if (ret == 42)
			fprintf(stderr,
			    "Document uses AES encryption which is not supported by this program!\n");
		else if (ret == EENCNF)
			fprintf(stderr,
			    "Error: Could not extract encryption information\n");
		else if (ret == ETRANF || ret == ETRENF || ret == ETRINF)
			fprintf(stderr,
			    "Error: Encryption not detected (is the document password protected?)\n");

		ret = 4;
		goto cleanup;
	} else if (cs.e.revision < 2 || (strcmp(cs.e.s_handler, "Standard") != 0)) {
		fprintf(stderr,
		    "The specific version is not supported (%s - %d)\n",
		    cs.e.s_handler, cs.e.revision);
		ret = 5;
		goto cleanup;
	}

	if (fclose(file)) {
		fprintf(stderr, "Error: closing file %s\n", inputfile);
	}
#ifdef UNPDF_DEBUG
	printEncData(&cs.e);
#endif
	/* try to initialize the cracking-engine */
	if (!initPDFCrack(&cs)) {
		fprintf(stderr, "Wrong userpassword given, '%s'\n",
		    userpassword);
		exit(-1);
	}

	/* deep serialize "e" structure */
	printf("%s:$pdf$%s*", inputfile, cs.e.s_handler);
	p = cs.e.o_string;
	for (i = 0; i < 32; i++)
		printf("%c%c", itoa16[ARCH_INDEX(p[i] >> 4)],
		    itoa16[ARCH_INDEX(p[i] & 0x0f)]);
	printf("*");
	p = cs.e.u_string;
	for (i = 0; i < 32; i++)
		printf("%c%c",
		    itoa16[ARCH_INDEX(p[i] >> 4)],
		    itoa16[ARCH_INDEX(p[i] & 0x0f)]);
	printf("*%d*", cs.e.fileIDLen);
	p = cs.e.fileID;
	for (i = 0; i < cs.e.fileIDLen; i++)
		printf("%c%c",
		    itoa16[ARCH_INDEX(p[i] >> 4)],
		    itoa16[ARCH_INDEX(p[i] & 0x0f)]);
	printf("*%d*%d*%d*%u*%u*%d*%d*%d*%d", cs.e.encryptMetaData,
	    cs.e.work_with_user, cs.e.have_userpassword, cs.e.version_major,
	    cs.e.version_minor, cs.e.length, cs.e.permissions, cs.e.revision,
	    cs.e.version);
	if (cs.e.have_userpassword)
		printf("*%s\n", userpassword);
	else
		printf("\n");
	exit(0);

      cleanup:

	return ret;
}

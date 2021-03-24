/*
 * This software is Copyright (c) 2013-2014 magnum, and it is hereby released
 * to the general public under the following terms:  Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 */

#ifdef AC_BUILT
#include "autoconfig.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif

#include "params.h"
#include "unicode.h"

// gcc -Wall -O3 -s -DNOT_JOHN -D_JOHN_MISC_NO_LOG cprepair.c unicode.c misc.c -o ../run/cprepair

static int sup, noguess, potfile, printable;
static int inv_cp, auto_cp;
struct options_main options;

#undef LINE_BUFFER_SIZE
#define LINE_BUFFER_SIZE 0x10000

#define TERM_RESET "\x1b[0m"

static void dump_hex(const void *msg, const void *x, unsigned int size)
{
	unsigned int i;

	printf("%s" TERM_RESET " : ", (char *)msg);
	for (i = 0; i < size; i++) {
		printf("%.2x", ((unsigned char*)x)[i]);
		if ((i % 4) == 3)
			printf(" ");
	}
	printf("\n");
}

/* There should be legislation against adding a BOM to UTF-8 */
inline static char *skip_bom(char *string)
{
	if (!memcmp(string, "\xEF\xBB\xBF", 3))
		string += 3;
	return string;
}

inline static int valid_ansi(const UTF16 *source)
{
	while (*source)
		if (*source++ & 0xff00)
			return 0;
	return 1;
}

inline static int contains_ascii_letters(const char *s)
{
	const UTF8 *source = (UTF8*)s;

	source--;
	while (*++source)
		if ((*source >= 'a' && *source <= 'z') ||
		    (*source >= 'A' && *source <= 'Z'))
			return 1;
	return 0;
}

static void usage(char *name, int retcode)
{
	puts("Codepage repair (c) magnum 2014-2019");
	puts("\nInput can be a mix of codepages, UTF-8 and double-encoded UTF-8, and with");
	puts("a mix of Windows (CRLF) and Unix (LF) line endings, or missing line endings");
	puts("on last lines.  If no file name is given, STDIN is used.");
	puts("Output is UTF-8 with LF line endings and no silly BOM.");
	printf("\nUsage: %s [options] [file(s)]\n", name);
	puts("Options:");
	puts(" -i <cp>   Codepage to assume for 8-bit input. Default is CP1252 (MS Latin-1)");
	puts(" -f <cp>   Alternate codepage when no ASCII letters (a-z, A-Z) seen (default");
	puts("           is to not treat them differently)");
	puts(" -n        Do not guess (leave 8-bit as-is)");
	puts(" -s        Suppress lines that does not need fixing.");
	puts(" -d        Debug (show conversions).");
	puts(" -l        List supported encodings.");
	puts(" -p        Only convert stuff after first ':' (.pot file).");
	puts(" -P        Suppress output lines with unprintable ASCII and, when used together");
	puts("           with -n option, also suppress lines with invalid UTF-8");

	exit(retcode);
}

static int process_file(char *name)
{
	FILE *fh;
	char orig[3 * LINE_BUFFER_SIZE + 1];

	if (!strcmp(name, "-")) {
		fh = stdin;
	} else {
		if (!(fh = fopen(name, "r"))) {
			perror("fopen");
			exit(0);
		}
	}

	while (!feof(fh)) {
		if (fgets(orig, sizeof(orig) - 1, fh)) {
			int len = -1;
			UTF16 u16[LINE_BUFFER_SIZE + 1];
			UTF8 u8buf[3 * LINE_BUFFER_SIZE + 1], *u8;
			char *out, *p, *plain, *convin;
			int valid;

			if ((p = strchr(orig, '\r'))) {
				*p++ = 0;
				len = (int)(p - orig);
				if (len > 3 * LINE_BUFFER_SIZE) {
					len = 3 * LINE_BUFFER_SIZE;
					orig[len] = 0;
				}
			} else
			if ((p = strchr(orig, '\n'))) {
				*p++ = 0;
				len = (int)(p - orig - 1);
				if (len > 3 * LINE_BUFFER_SIZE) {
					len = 3 * LINE_BUFFER_SIZE;
					orig[len] = 0;
				}
			} else
				len = strlen(orig);

			if (options.verbosity >= VERB_MAX)
				dump_hex(orig, orig, len);

			plain = strchr(orig, ':');
			if (potfile && plain) {
				len -= (++plain - orig);
				convin = plain;
				if (options.verbosity >= VERB_MAX)
					dump_hex(convin, convin, len);
			} else
				convin = skip_bom(orig);

			out = convin;
			valid = valid_utf8((UTF8*)convin);

			if (!valid) {
				if (noguess) {
					if (printable) {
						if (options.verbosity > VERB_DEFAULT)
							fprintf(stderr, "%s" TERM_RESET " skipped (invalid UTF-8)\n", convin);
						continue;
					} else
						out = convin;
				} else {
					if (auto_cp != inv_cp)
						options.internal_cp =
							options.target_enc =
							contains_ascii_letters(convin) ?
							inv_cp : auto_cp;
					else
						options.internal_cp =
							options.target_enc =
							inv_cp;
					initUnicode(0);

					enc_to_utf16(u16, sizeof(u16), (UTF8*)convin, len);
					out = (char*)utf16_to_utf8_r(u8buf, sizeof(u8buf), u16);
					if (options.verbosity > VERB_DEFAULT &&
					    strcmp(convin, out))
						fprintf(stderr, "%s" TERM_RESET " -> ", orig);
				}
			} else if (valid > 1) {
				char dd[3 * LINE_BUFFER_SIZE + 1];
				int level = 0;

				/* Unroll any number of levels of double-conversions */
				strcpy (dd, convin);
				while (*convin) {
					out = dd;
					utf8_to_utf16(u16, sizeof(u16),
					              (UTF8*)dd, len);
					if (!valid_ansi(u16))
						break;
					options.internal_cp =
						options.target_enc =
						ISO_8859_1;
					initUnicode(0);
					u8 = utf16_to_enc_r(u8buf,
						sizeof(u8buf), u16);
					if (!strcmp((char*)u8, dd) ||
					    !valid_utf8(u8))
						break;
					strcpy(dd, (char*)u8);
					level++;
				}
				if (level && options.verbosity > VERB_DEFAULT)
					fprintf(stderr, "Double-encoding in %d level%s: ", level,
					        level > 1 ? "s" : "");

				if (options.verbosity > VERB_DEFAULT &&
				    strcmp(convin, out))
					fprintf(stderr, "%s" TERM_RESET " => ", convin);
			}

			if (printable) {
				unsigned char *p = (unsigned char*)out;
				int len = strlen(out);
				int skip = 0;

				while (len--) {
					if ((*p < 0x20 && *p != '\t') || *p == 0x7f) {
						if (options.verbosity > VERB_DEFAULT)
							fprintf(stderr, "%s" TERM_RESET " skipped (unprintables)\n", convin);
						skip = 1;
						break;
					} else
						p++;
				}
				if (skip)
					continue;
			}

			if (!sup || (strcmp(convin, out))) {
				if (potfile && plain > orig) {
					*--plain = 0;
					printf("%s:%s\n", orig, out);
				} else
					puts(out);
			}
		}
	}
	fclose(fh);

	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	int c;

	options.verbosity = VERB_DEFAULT;

	while ((c = getopt(argc, argv, "si:f:hldpnP")) != -1) {
		switch (c) {
		case 's':
			sup = 1;
			break;
		case 'd':
			options.verbosity++;
			break;
		case 'p':
			potfile++;
			break;
		case 'n':
			noguess = 1;
			break;
		case 'P':
			printable = 1;
			break;
		case 'f':
			auto_cp = cp_name2id(optarg, 1);
			break;
		case 'i':
			inv_cp = cp_name2id(optarg, 1);
			break;
		case 'l':
			puts("Supported encodings:");
			listEncodings(stdout);
			exit(EXIT_SUCCESS);
			break;
		case 'h':
			usage(argv[0], EXIT_SUCCESS);
			break;
		default:
			usage(argv[0], EXIT_FAILURE);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	options.input_enc = UTF_8;

	if (!inv_cp)
		inv_cp = CP1252;

	if (!auto_cp)
		auto_cp = inv_cp;

	if (argc == 0)
		return process_file("-");
	else
	while (*argv) {
		int ret;

		if (options.verbosity > VERB_DEFAULT)
			fprintf(stderr, "filename: %s\n", *argv);
		ret = process_file(*argv++);
		if (ret != EXIT_SUCCESS)
			return ret;
	}

	return EXIT_SUCCESS;
}
